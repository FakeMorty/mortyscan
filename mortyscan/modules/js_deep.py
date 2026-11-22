"""Глубокий read-only анализ JS-бандлов и source maps."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunsplit

import httpx

from ..core import Finding, ScanContext, Severity, host_in_scope
from .crawler import _registrable

NAME = "js_deep"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False
MAX_JS_BYTES = 2 * 1024 * 1024
MAX_MAP_BYTES = 4 * 1024 * 1024

_ENDPOINT_RE = re.compile(
    r"[\"'`](?P<url>(?:/api(?:/[^\"'`\s]*)?|/v\d+/(?:[^\"'`\s]+)?|https?://[^\"'`\s]{4,240}))[\"'`]",
    re.I,
)
_CALL_RE = re.compile(
    r"(?:fetch|axios\.[a-z]+)\s*\(\s*[\"'`](?P<url>[^\"'`]{1,240})[\"'`]",
    re.I,
)
_SOURCEMAP_RE = re.compile(r"(?m)(?://#|//@|/\*#)\s*sourceMappingURL\s*=\s*([^\s*]+)")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# Each detector captures credential-like content; evidence stores only a digest, never the value.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    ("AWS access key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), Severity.HIGH),
    ("AWS secret access key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{32,})"), Severity.CRITICAL),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), Severity.HIGH),
    ("Stripe live secret", re.compile(r"\b(sk_live_[0-9A-Za-z]{24,})\b"), Severity.CRITICAL),
    ("Slack token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{20,})\b"), Severity.HIGH),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"), Severity.CRITICAL),
    ("JWT token", JWT_RE, Severity.MEDIUM),
    ("Private key PEM", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("Generic secret assignment", re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|secret|token|password)\b\s*[:=]\s*[\"']([^\"']{16,})[\"']"), Severity.HIGH),
    ("Bearer token", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{24,}={0,2})"), Severity.HIGH),
    ("npm token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), Severity.CRITICAL),
    ("SendGrid API key", re.compile(r"\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b"), Severity.CRITICAL),
    ("Twilio API key", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), Severity.HIGH),
    ("Mailgun API key", re.compile(r"\b(key-[0-9a-fA-F]{32})\b"), Severity.CRITICAL),
    ("Discord bot token", re.compile(r"\b([MN][A-Za-z\d]{23,28}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27})\b"), Severity.HIGH),
    ("Telegram bot token", re.compile(r"\b(\d{8,12}:[A-Za-z0-9_-]{30,})\b"), Severity.HIGH),
    ("OpenAI API key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b"), Severity.CRITICAL),
    ("Anthropic API key", re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{32,})\b"), Severity.CRITICAL),
    ("Hugging Face token", re.compile(r"\b(hf_[A-Za-z0-9]{30,})\b"), Severity.HIGH),
    ("DigitalOcean token", re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"), Severity.CRITICAL),
    ("Shopify private token", re.compile(r"\b(shpat_[A-Za-z0-9]{32,}|shpca_[A-Za-z0-9]{32,}|shppa_[A-Za-z0-9]{32,}|shpss_[A-Za-z0-9]{32,})\b"), Severity.HIGH),
    ("Square access token", re.compile(r"\b(sq0atp-[A-Za-z0-9_-]{22,})\b"), Severity.CRITICAL),
    ("Google OAuth client secret", re.compile(r"\b(GOCSPX-[A-Za-z0-9_-]{20,})\b"), Severity.HIGH),
)
_PLACEHOLDERS = ("example", "your_key_here", "your-api-key", "changeme", "placeholder", "xxx", "fake", "test_key")


def _in_scope(url: str, ctx: ScanContext) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        configured_scope = set(ctx.config.get("scope_hosts", []))
        if configured_scope:
            return host_in_scope(parsed.hostname, configured_scope)
        return _registrable(parsed.hostname) == _registrable(ctx.target)
    except Exception:
        return False


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    return any(word in normalized for word in _PLACEHOLDERS)


def _collect_secrets(ctx: ScanContext, source_url: str, text: str, *, source_map: bool = False) -> int:
    matches: set[tuple[str, str, int]] = set()
    known = ctx.config.setdefault("_js_secret_fingerprints", set())
    for label, pattern, severity in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            if _is_placeholder(value):
                continue
            digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
            line = text.count("\n", 0, match.start()) + 1
            key = (label, digest, line)
            fingerprint = digest
            if key in matches or fingerprint in known:
                continue
            matches.add(key)
            known.add(fingerprint)
            if label == "JWT token":
                ctx.seen_jwts.add(value)
            ctx.add(Finding(
                module=NAME,
                title=f"Возможный секрет в JavaScript: {label}",
                severity=severity, cwe="CWE-798", url=urlunsplit((*urlparse(source_url)[:3], "", "")),
                evidence=f"line={line}; SHA-256={digest}; длина={len(value)} (значение скрыто)",
                description=("В JS-коде найдена строка, похожая на credential. Регулярное выражение не подтверждает "
                             "валидность ключа; проверьте вручную и отзовите его, если он действующий."),
                remediation="Удалите секрет из клиентского кода, отзовите/перевыпустите credential и перенесите его на серверную сторону.",
                source="source map" if source_map else "JavaScript bundle",
                confidence="medium", tags=["secret", "javascript", "source-map" if source_map else "bundle"],
                raw={"secret_type": label, "sha256": digest, "line": line},
            ))
    return len(matches)


def _collect_endpoints(ctx: ScanContext, js_url: str, text: str) -> set[str]:
    endpoints: set[str] = set()
    for pattern in (_ENDPOINT_RE, _CALL_RE):
        for match in pattern.finditer(text):
            candidate = match.group("url").strip()
            if candidate.startswith(("data:", "javascript:", "mailto:")):
                continue
            if not candidate.startswith(("http://", "https://", "/")):
                if pattern is _ENDPOINT_RE or not re.fullmatch(r"[A-Za-z0-9_./?=&%:-]{1,240}", candidate):
                    continue
            absolute = urljoin(js_url, candidate)
            parsed = urlparse(absolute)
            if parsed.scheme in {"http", "https"}:
                # Query values can contain bearer tokens; endpoints are inventory, not replay URLs.
                endpoints.add(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))[:500])
    ctx.endpoints.update(endpoints)
    return endpoints


async def _fetch_resource(client: httpx.AsyncClient, ctx: ScanContext, url: str, limit: int):
    if not _in_scope(url, ctx):
        return None
    try:
        async with client.stream("GET", url, follow_redirects=False,
                                 headers={"Range": f"bytes=0-{limit - 1}"}) as response:
            if response.status_code not in {200, 206}:
                return None
            chunks = []
            size = 0
            async for chunk in response.aiter_bytes():
                if size >= limit:
                    break
                part = chunk[:limit - size]
                chunks.append(part)
                size += len(part)
            return b"".join(chunks), response.headers.get("content-type", "")
    except Exception:
        return None


def _write_sources(ctx: ScanContext, map_url: str, sources: list[str], contents: list[str | None]) -> list[str]:
    if not ctx.config.get("save_sourcemaps"):
        return []
    output = ctx.case_dir / "sourcemaps"
    output.mkdir(parents=True, exist_ok=True)
    saved = []
    total = int(ctx.config.get("_sourcemap_saved_bytes", 0))
    for index, (source, content) in enumerate(zip(sources, contents)):
        if not content:
            continue
        data = content.encode("utf-8", errors="replace")
        if len(data) > 1_000_000 or total + len(data) > 20_000_000:
            continue
        digest = hashlib.sha256((map_url + str(source)[:1000] + str(index)).encode()).hexdigest()[:16]
        path = output / f"{digest}.js"
        path.write_bytes(data)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        saved.append(path.name)
        total += len(data)
    ctx.config["_sourcemap_saved_bytes"] = total
    return saved


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    scripts = set(ctx.script_urls)
    scripts.update(url for url in ctx.crawled_urls if urlparse(url).path.lower().split("?", 1)[0].endswith(".js"))
    scripts = {url for url in scripts if _in_scope(url, ctx)}
    max_files = max(1, min(100, int(ctx.config.get("js_max_files", 50))))
    scripts = set(sorted(scripts)[:max_files])
    semaphore = asyncio.Semaphore(8)
    maps: set[str] = set()
    analyzed = 0
    endpoint_count = 0
    initial_endpoints = set(ctx.endpoints)
    secret_count = 0
    map_sources = 0

    async def analyze_script(url: str) -> None:
        nonlocal analyzed, endpoint_count, secret_count
        async with semaphore:
            fetched = await _fetch_resource(client, ctx, url, MAX_JS_BYTES)
        if not fetched:
            return
        data, _ = fetched
        text = data.decode("utf-8", errors="replace")
        analyzed += 1
        endpoint_count += len(_collect_endpoints(ctx, url, text))
        secret_count += _collect_secrets(ctx, url, text)
        for match in _SOURCEMAP_RE.finditer(text):
            ref = match.group(1).strip().strip("'\"`")
            if ref.startswith("data:"):
                continue
            map_url = urljoin(url, ref)
            if _in_scope(map_url, ctx) and urlparse(map_url).path.lower().endswith(".map"):
                maps.add(map_url)

    await asyncio.gather(*(analyze_script(url) for url in sorted(scripts)))

    async def analyze_map(map_url: str) -> None:
        nonlocal secret_count, map_sources
        fetched = await _fetch_resource(client, ctx, map_url, MAX_MAP_BYTES)
        if not fetched:
            return
        raw, _ = fetched
        try:
            source_map = json.loads(raw.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if not isinstance(source_map, dict):
            return
        sources = source_map.get("sources") or []
        contents = source_map.get("sourcesContent") or []
        if not isinstance(sources, list) or not isinstance(contents, list):
            return
        contents = [content if isinstance(content, str) else None for content in contents]
        source_count = sum(content is not None for content in contents)
        if source_count:
            map_sources += source_count
            saved = _write_sources(ctx, map_url, sources, contents)
            ctx.add(Finding(
                module=NAME,
                title="Source map раскрывает исходный код",
                severity=Severity.HIGH, cwe="CWE-540", url=urlunsplit((*urlparse(map_url)[:3], "", "")),
                evidence=f"sources={len(sources)}; sourcesContent={source_count}; сохранено локально={len(saved)}",
                description="Публичная source map содержит исходные файлы. Это может раскрывать внутреннюю логику и комментарии; содержимое не прикладывается к отчёту.",
                remediation="Отключите публикацию source maps в production или ограничьте доступ. Проверьте их на секреты и внутренние URL.",
                source="source map JSON", confidence="high", tags=["source-map", "source-code"],
                raw={"source_count": len(sources), "sources_content_count": source_count,
                     "saved_files": saved},
            ))
            for source, content in zip(sources, contents):
                if not content:
                    continue
                source_url = f"{map_url}#source={source}"
                secret_count += _collect_secrets(ctx, source_url, content, source_map=True)
                _collect_endpoints(ctx, map_url, content)

    await asyncio.gather(*(analyze_map(url) for url in sorted(maps)[:30]))
    endpoint_count = len(ctx.endpoints - initial_endpoints)
    ctx.add(Finding(
        module=NAME,
        title=f"Анализ JavaScript завершён: bundle {analyzed}, source maps {min(len(maps), 30)}",
        severity=Severity.INFO,
        description="Извлечены URL-пути и проверены JS/source maps; значения секретов не сохраняются в evidence.",
        raw={"script_files": analyzed, "source_maps": min(len(maps), 30),
             "endpoints_found": endpoint_count, "potential_secrets": secret_count,
             "source_contents": map_sources},
    ))
