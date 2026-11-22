"""Проверка параметров URL на Open Redirect без перехода по внешним редиректам."""
from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "redirect"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False

PARAM_NAMES = {
    "redirect", "redirect_uri", "return", "return_to", "returnurl", "next", "url",
    "target", "dest", "destination", "continue", "callback", "callbackurl", "goto",
    "r", "u", "link", "out", "view", "file", "forward", "location", "redir",
    "referer", "ref",
}
PROBE_HOST = "evil.mortyscan.invalid"
PAYLOADS = (
    f"//{PROBE_HOST}",
    f"https://{PROBE_HOST}/",
    f"//{PROBE_HOST}/%2F..",
    f"/\\{PROBE_HOST}",
    f"https://target.invalid@{PROBE_HOST}/",
    f"https:{PROBE_HOST}",
    f"//{PROBE_HOST}?x=target.invalid",
)
_REDIRECT_SINK_RE = re.compile(r"(?:<meta[^>]+refresh|window\.location|location\.(?:href|assign|replace))", re.I)


class _Gate:
    def __init__(self, rate: float, *, enabled: bool = True) -> None:
        self.enabled = enabled
        self.interval = 1 / max(0.1, rate)
        self.lock = asyncio.Lock()
        self.last = 0.0

    async def wait(self) -> None:
        if not self.enabled:
            return
        async with self.lock:
            delay = self.interval - (time.monotonic() - self.last)
            if delay > 0:
                await asyncio.sleep(delay)
            self.last = time.monotonic()


def _targets(ctx: ScanContext) -> list[tuple[str, str]]:
    routes: dict[str, set[str]] = {}
    for url in ctx.crawled_urls:
        parsed = urlparse(url)
        if parsed.hostname != ctx.target or parsed.scheme not in {"http", "https"}:
            continue
        keys = {key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        routes[urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))] = keys
    for path, keys in ctx.discovered_params.items():
        url = urljoin(ctx.base_url, path)
        parsed = urlparse(url)
        if parsed.hostname == ctx.target:
            base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
            routes.setdefault(base, set()).update(keys)
    for form in ctx.discovered_forms:
        if str(form.get("method", "GET")).upper() != "GET":
            continue
        url = str(form.get("url", ""))
        if urlparse(url).hostname != ctx.target:
            continue
        routes.setdefault(url, set()).update(str(field.get("name", "")) for field in form.get("inputs", []))

    result = []
    for url, discovered in sorted(routes.items()):
        names = {name for name in discovered if name}
        names.update(PARAM_NAMES)
        for name in sorted(names):
            result.append((url, name))
    return result


def _external_location(base_url: str, location: str) -> bool:
    try:
        host = (urlparse(urljoin(base_url, location)).hostname or "").lower().rstrip(".")
        return host == PROBE_HOST or host.endswith("." + PROBE_HOST)
    except Exception:
        return False


def _html_redirect(body: str) -> bool:
    return bool(PROBE_HOST in body.lower() and _REDIRECT_SINK_RE.search(body))


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    if not ctx.permissions.get("intrusive"):
        return
    targets = _targets(ctx)
    max_requests = max(1, min(1000, int(ctx.config.get("redirect_max_requests", 60))))
    targets = targets[:100]
    gate = _Gate(float(ctx.config.get("rate_limit", 10.0)),
                 enabled=not ctx.config.get("_client_rate_limited", False))
    seen: set[tuple[str, str]] = set()
    semaphore = asyncio.Semaphore(10)
    requests_sent = 0

    async def probe(url: str, name: str, payload: str) -> None:
        async with semaphore:
            await gate.wait()
            try:
                response = await client.get(url, params={name: payload}, follow_redirects=False)
            except Exception:
                return
        if response.is_redirect and _external_location(url, response.headers.get("location", "")):
            key = (url, name)
            if key in seen:
                return
            seen.add(key)
            parsed = urlparse(url)
            oauth = name.lower() == "redirect_uri" and any(token in parsed.path.lower() for token in ("oauth", "authorize", "login"))
            ctx.add(Finding(
                module=NAME,
                title=f"Открытый редирект в параметре «{name}»" + (" (OAuth-контекст)" if oauth else ""),
                severity=Severity.HIGH if oauth else Severity.MEDIUM,
                cwe="CWE-601", url=str(response.request.url),
                evidence=f"HTTP {response.status_code}; Location={response.headers.get('location', '')[:300]}; probe={payload!r}",
                description="Сервер перенаправил браузер на внешний проверочный домен. Такие редиректы могут использоваться в фишинге; в OAuth-контексте также проверьте строгую валидацию redirect_uri.",
                remediation="Разрешайте только относительные пути или сверяйте полный origin с точным allowlist. Не используйте проверку по подстроке/суффиксу.",
                source="HTTP Location", confidence="high", tags=["redirect", "active-probe"],
            ))
            return
        if response.status_code == 200 and _html_redirect(response.text[:65536]):
            key = (url, name)
            if key in seen:
                return
            seen.add(key)
            ctx.add(Finding(
                module=NAME,
                title=f"Возможный клиентский Open Redirect в параметре «{name}»",
                severity=Severity.MEDIUM, cwe="CWE-601", url=str(response.request.url),
                evidence=f"HTTP 200; найден redirect sink с {PROBE_HOST}; probe={payload!r}",
                description="В HTML-ответе одновременно обнаружены проверочный внешний адрес и meta refresh/window.location. Проверьте вручную, что значение действительно управляет навигацией.",
                remediation="Валидируйте redirect target на сервере и предпочитайте локальные относительные пути.",
                source="HTML redirect sink", confidence="medium", tags=["redirect", "active-probe"],
            ))

    for url, name in targets:
        for payload in PAYLOADS:
            if requests_sent >= max_requests:
                break
            requests_sent += 1
            await probe(url, name, payload)
        if requests_sent >= max_requests:
            break
    ctx.add(Finding(
        module=NAME, title=f"Проверка Open Redirect завершена: параметров {len(targets)}",
        severity=Severity.INFO,
        description="Проверялись только GET-параметры известных страниц; внешние редиректы не переходились.",
        raw={"parameters_checked": len(targets), "requests_sent": requests_sent,
             "confirmed": len(seen), "max_requests": max_requests},
    ))
