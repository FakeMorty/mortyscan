"""Вежливый асинхронный краулер. Не выходит за scope (тот же регистрируемый домен).
Собирает: URL, формы, query-параметры, эндпоинты в JS-файлах.
Попутно ищет утечки секретов (API-ключи, токены)."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup

try:
    import tldextract
    _ext = tldextract.TLDExtract(suffix_list_urls=())
except ImportError:
    _ext = None

from ..core import Finding, ScanContext, Severity

NAME = "crawler"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False

JS_ENDPOINT_RE = re.compile(
    r"""['"`](/[a-zA-Z0-9_\-./?=&%]{2,200})['"`]""",
)
SECRET_PATTERNS = [
    ("ключ AWS",         re.compile(r"AKIA[0-9A-Z]{16}")),
    ("ключ Google API",  re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("токен Slack",      re.compile(r"xox[abprs]-[0-9A-Za-z\-]{10,48}")),
    ("приватный ключ",   re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----")),
    ("JWT-токен",        re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("ключ Stripe",      re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("ключ GitHub",      re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("токен Telegram-бота", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b")),
]


def _registrable(host: str) -> str:
    if _ext:
        e = _ext(host)
        return ".".join(p for p in [e.domain, e.suffix] if p) or host
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _in_scope(url: str, scope_domain: str) -> bool:
    try:
        h = urlparse(url).hostname or ""
        return _registrable(h) == scope_domain
    except Exception:
        return False


async def _fetch(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    try:
        return await client.get(url)
    except Exception:
        return None


async def _seed_urls(client: httpx.AsyncClient, base: str) -> list[str]:
    seeds = [base]
    for path in ("/robots.txt", "/sitemap.xml", "/sitemap_index.xml"):
        r = await _fetch(client, urljoin(base, path))
        if not r or r.status_code != 200:
            continue
        text = r.text
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith(("allow:", "disallow:", "sitemap:")):
                _, _, val = line.partition(":")
                val = val.strip()
                if val.startswith("/"):
                    seeds.append(urljoin(base, val))
                elif val.startswith("http"):
                    seeds.append(val)
        for m in re.findall(r"<loc>([^<]+)</loc>", text):
            seeds.append(m.strip())
    return seeds


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    base = ctx.base_url
    scope = _registrable(urlparse(base).hostname or ctx.target)

    max_pages = int(ctx.config.get("crawl_max", 80))
    max_depth = int(ctx.config.get("crawl_depth", 3))

    seeds = await _seed_urls(client, base)
    queue: asyncio.Queue = asyncio.Queue()
    for s in seeds:
        await queue.put((s, 0))

    seen: set[str] = set()
    forms: list[dict] = []
    params: dict[str, set[str]] = {}
    secrets_seen: set[tuple[str, str]] = set()

    async def worker():
        while True:
            try:
                url, depth = await asyncio.wait_for(queue.get(), timeout=2)
            except asyncio.TimeoutError:
                return
            try:
                if url in seen or len(seen) >= max_pages or not _in_scope(url, scope):
                    continue
                seen.add(url)
                r = await _fetch(client, url)
                if not r:
                    continue
                ctype = r.headers.get("content-type", "")
                pu = urlparse(url)
                if pu.query:
                    for k, vs in parse_qs(pu.query).items():
                        params.setdefault(pu.path, set()).add(k)

                if "text/html" in ctype:
                    soup = BeautifulSoup(r.text, "lxml")
                    for f in soup.find_all("form"):
                        action = urljoin(url, f.get("action") or url)
                        method = (f.get("method") or "GET").upper()
                        inputs = []
                        for i in f.find_all(["input", "textarea", "select"]):
                            name = i.get("name")
                            if name:
                                inputs.append({
                                    "name": name,
                                    "type": i.get("type", "text"),
                                    "value": i.get("value", ""),
                                })
                        if _in_scope(action, scope):
                            forms.append({"url": action, "method": method, "inputs": inputs})
                    if depth < max_depth:
                        for a in soup.find_all(["a", "link"]):
                            href = a.get("href")
                            if not href: continue
                            nxt = urljoin(url, href).split("#")[0]
                            if _in_scope(nxt, scope) and nxt not in seen:
                                await queue.put((nxt, depth + 1))
                        for s in soup.find_all("script", src=True):
                            nxt = urljoin(url, s["src"])
                            if _in_scope(nxt, scope) and nxt not in seen:
                                await queue.put((nxt, depth + 1))
                elif "javascript" in ctype or url.endswith(".js"):
                    for m in JS_ENDPOINT_RE.findall(r.text):
                        nxt = urljoin(base, m).split("#")[0]
                        if _in_scope(nxt, scope) and nxt not in seen and len(seen) < max_pages:
                            await queue.put((nxt, depth + 1))

                # Поиск утечек секретов
                if r.text and len(r.text) < 1_000_000:
                    for label, pat in SECRET_PATTERNS:
                        for m in pat.findall(r.text):
                            key = (label, str(m)[:40])
                            if key in secrets_seen: continue
                            secrets_seen.add(key)
                            ctx.add(Finding(
                                module=NAME,
                                title=f"Возможная утечка секрета: {label}",
                                severity=Severity.CRITICAL, cwe="CWE-798",
                                url=url,
                                evidence=str(m)[:80],
                                description=f"В ответе сервера обнаружена строка, похожая на {label}. "
                                            "Такие данные не должны оказываться в публичном доступе.",
                                remediation="1) НЕМЕДЛЕННО отзовите/перевыпустите этот секрет. "
                                            "2) Найдите, откуда он попал в ответ, и уберите из исходников. "
                                            "3) Используйте переменные окружения или vault. "
                                            "4) Настройте pre-commit хуки (gitleaks, trufflehog).",
                            ))
            except Exception:
                pass
            finally:
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(8)]
    await asyncio.gather(*workers, return_exceptions=True)

    ctx.crawled_urls.update(seen)
    ctx.discovered_forms.extend(forms)
    for k, v in params.items():
        ctx.discovered_params.setdefault(k, set()).update(v)

    ctx.add(Finding(
        module=NAME,
        title=f"Краул завершён: страниц {len(seen)}, форм {len(forms)}, "
              f"параметров {sum(len(v) for v in params.values())}",
        severity=Severity.INFO,
        description="Краулер обошёл сайт и собрал ссылки, формы и параметры запросов. "
                    "Этот «инвентарь» будет использован модулями vulns и discovery.",
        raw={"urls": sorted(seen)[:200], "forms_count": len(forms),
             "params": {k: sorted(v) for k, v in params.items()}},
    ))
