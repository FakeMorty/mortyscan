"""Optional Playwright SPA crawler, XHR inventory, and DOM-XSS dialog confirmation."""
from __future__ import annotations

import asyncio
import logging
import re
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from ..core import Finding, ScanContext, Severity, host_in_scope
from .crawler import _registrable
from .jwt_audit import JWT_RE

NAME = "browser"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False
LOG = logging.getLogger("mortyscan.browser")


class _RateGate:
    def __init__(self, rate: float):
        self.interval = 1.0 / max(0.1, rate)
        self.lock = asyncio.Lock()
        self.last = 0.0

    async def wait(self) -> None:
        async with self.lock:
            delay = self.interval - (time.monotonic() - self.last)
            if delay > 0:
                await asyncio.sleep(delay)
            self.last = time.monotonic()


def _safe_console(text: str) -> str:
    text = re.sub(r"(?i)(authorization|cookie|token|password|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+",
                  r"\1=[redacted]", text)
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/-]{12,}", "Bearer [redacted]", text)
    text = JWT_RE.sub("[JWT redacted]", text)
    text = re.sub(r"(https?://[^\s?#]+)\?[^\s#]+", r"\1?[query redacted]", text)
    return text[:400]


def _in_scope(url: str, ctx: ScanContext) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        scope = set(ctx.config.get("scope_hosts", []))
        if scope:
            return host_in_scope(parsed.hostname, scope)
        return _registrable(parsed.hostname) == _registrable(ctx.target)
    except Exception:
        return False


def _page_url_with_payload(item: dict) -> str:
    url = str(item.get("url", ""))
    if str(item.get("method", "GET")).upper() != "GET":
        return ""
    parts = urlparse(url)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    param = str(item.get("param", ""))
    if param:
        params[param] = "<script>alert(1)</script>"
    if not params:
        return ""
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, urlencode(params), ""))


def _browser_cookies(value: str, host: str, secure: bool) -> list[dict]:
    result = []
    for item in value.split(";"):
        name, sep, content = item.strip().partition("=")
        if sep and name and not any(ch in name + content for ch in "\r\n"):
            result.append({"name": name, "value": content, "domain": host, "path": "/", "secure": secure})
    return result


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    del client
    if not ctx.config.get("browser_enabled"):
        return
    if not ctx.permissions.get("intrusive"):
        ctx.add(Finding(module=NAME, title="Браузерный анализ пропущен: нет активного разрешения",
                        severity=Severity.INFO, source="permission gate", confidence="high"))
        return
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        LOG.warning("optional dependency missing: playwright; browser module skipped")
        ctx.add(Finding(module=NAME, title="Playwright не установлен — браузерный анализ пропущен",
                        severity=Severity.INFO,
                        description="Установите MortyScan с extra [browser], затем выполните playwright install chromium.",
                        source="optional dependency", confidence="high"))
        return

    endpoints: set[str] = set()
    scripts: set[str] = set()
    console_errors: set[str] = set()
    confirmed: set[str] = set()
    screenshots = bool(ctx.config.get("screenshots"))
    screenshot_names: list[str] = []
    screenshot_dir = ctx.case_dir / "screenshots"
    if screenshots:
        screenshot_dir.mkdir(parents=True, exist_ok=True)

    base = urlparse(ctx.base_url)
    auth_headers = {}
    for raw in ctx.config.get("request_headers", []):
        name, sep, value = str(raw).partition(":")
        if sep and name.strip() and not any(c in raw for c in "\r\n"):
            auth_headers[name.strip()] = value.strip()
    proxy = ctx.config.get("proxy")
    launch_options = {"headless": True}
    if proxy:
        launch_options["proxy"] = {"server": str(proxy)}
    xss_candidates = [item for item in ctx.xss_candidates
                      if str(item.get("method", "GET")).upper() == "GET" and _page_url_with_payload(item)]
    rate_gate = _RateGate(float(ctx.config.get("rate_limit", 10.0)))

    async def scan_page(page, url: str, dom_candidate: dict | None = None) -> None:
        if not _in_scope(url, ctx):
            return
        dialog_seen = asyncio.Event()
        async def on_dialog(dialog):
            dialog_seen.set()
            try:
                await dialog.dismiss()
            except Exception:
                pass
        page.on("dialog", on_dialog)
        started = asyncio.get_running_loop().time()
        try:
            await asyncio.wait_for(page.goto(url, wait_until="domcontentloaded", timeout=60000), timeout=60)
            try:
                await page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass
            if dom_candidate and dialog_seen.is_set():
                confirmed.add(url)
            if screenshots and len(screenshot_names) < 4:
                name = f"page-{len(screenshot_names) + 1:03d}.png"
                await page.screenshot(path=str(screenshot_dir / name), full_page=False, timeout=10000)
                screenshot_names.append(f"screenshots/{name}")
        except asyncio.TimeoutError:
            LOG.warning("browser page hard timeout: %s", urlparse(url).path)
        except Exception as exc:
            console_errors.add(f"navigation {urlparse(url).path}: {type(exc).__name__}")
        finally:
            page.remove_listener("dialog", on_dialog)
            if asyncio.get_running_loop().time() - started > 60:
                LOG.warning("browser page exceeded 60 seconds: %s", urlparse(url).path)

    browser = None
    context = None
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(**launch_options)
            context = await browser.new_context(extra_http_headers=auth_headers)
            if ctx.config.get("cookie"):
                await context.add_cookies(_browser_cookies(str(ctx.config["cookie"]), base.hostname or ctx.target,
                                                           base.scheme == "https"))

            async def route_guard(route):
                request_url = route.request.url
                if not _in_scope(request_url, ctx):
                    await route.abort()
                    return
                await rate_gate.wait()
                # Do not forward custom auth headers or cookies to a different in-scope origin.
                parsed = urlparse(request_url)
                if parsed.hostname != base.hostname or parsed.scheme != base.scheme or parsed.port != base.port:
                    headers = dict(route.request.headers)
                    for name in list(headers):
                        if name.lower() in {key.lower() for key in auth_headers} | {"cookie", "authorization"}:
                            headers.pop(name, None)
                    await route.continue_(headers=headers)
                    return
                await route.continue_()

            await context.route("**/*", route_guard)
            page = await context.new_page()

            def collect_request(request):
                if not _in_scope(request.url, ctx):
                    return
                if request.resource_type in {"xhr", "fetch"} and len(endpoints) < 1000:
                    endpoints.add(request.url.split("#", 1)[0])
                if urlparse(request.url).path.lower().endswith(".js") and len(scripts) < 500:
                    scripts.add(request.url.split("#", 1)[0])

            def collect_console(message):
                if message.type == "error" and len(console_errors) < 500:
                    console_errors.add(_safe_console(message.text))

            page.on("request", collect_request)
            page.on("console", collect_console)
            await scan_page(page, ctx.base_url)
            for item in xss_candidates[:20]:
                test_url = _page_url_with_payload(item)
                if test_url:
                    await scan_page(page, test_url, item)
                    if test_url in confirmed:
                        ctx.add(Finding(
                            module=NAME, title="DOM-XSS подтверждена диалогом браузера",
                            severity=Severity.CRITICAL, cwe="CWE-79", cvss=9.0,
                            url=urlunparse((*urlparse(test_url)[:3], "", "")),
                            evidence=f"browser dialog triggered for parameter={str(item.get('param', ''))[:80]}",
                            description="В браузере появилось JavaScript-диалоговое окно после навигации по отражённому XSS URL.",
                            remediation="Экранируйте вывод и исключите небезопасные DOM sinks.",
                            source="Playwright dialog", confidence="confirmed", tags=["xss", "dom-xss", "confirmed"],
                        ))
            try:
                storage = await page.evaluate("() => Object.entries(localStorage).map(([k,v]) => [k,v])")
            except Exception:
                storage = []
            for cookie in await context.cookies():
                for match in JWT_RE.findall(str(cookie.get("value", ""))):
                    ctx.seen_jwts.add(match)
            for key, value in storage if isinstance(storage, list) else []:
                for match in JWT_RE.findall(str(value)):
                    ctx.seen_jwts.add(match)
            if screenshots:
                screenshot = screenshot_dir / "thumbnail.png"
                if not screenshot.exists():
                    try:
                        await page.screenshot(path=str(screenshot), full_page=False, timeout=5000)
                        screenshot_names.append("screenshots/thumbnail.png")
                    except Exception:
                        pass
            await context.close()
            context = None
            await browser.close()
            browser = None
    except Exception as exc:
        for resource in (context, browser):
            if resource is not None:
                try:
                    await resource.close()
                except Exception:
                    pass
        LOG.warning("browser module failed: %s", type(exc).__name__)
        ctx.add(Finding(module=NAME, title="Браузерный анализ завершился с ошибкой",
                        severity=Severity.INFO, description=f"Playwright: {type(exc).__name__}.",
                        source="optional browser", confidence="low"))
        return

    # Endpoints are inventory only; query values are deliberately removed to avoid reporting tokens.
    for url in endpoints:
        parsed = urlparse(url)
        ctx.endpoints.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", "")))
    ctx.script_urls.update(url for url in scripts if _in_scope(url, ctx))
    for screenshot_path in screenshot_names:
        ctx.add(Finding(module=NAME, title="Скриншот браузерной страницы", severity=Severity.INFO,
                        description="Локальный снимок страницы; содержимое страницы может включать приватные данные авторизованной сессии.",
                        source="Playwright screenshot", confidence="high",
                        raw={"screenshot": screenshot_path}))
    if console_errors:
        ctx.add(Finding(module=NAME, title=f"Browser console: ошибок {len(console_errors)}",
                        severity=Severity.INFO,
                        evidence="\n".join(sorted(console_errors)[:20]),
                        description="Собраны сообщения console.error; сообщения отфильтрованы по длине и маскированию credential-подобных полей.",
                        source="Playwright console", confidence="medium"))
    ctx.add(Finding(module=NAME, title="Браузерный анализ завершён",
                    severity=Severity.INFO,
                    description="Собраны same-scope XHR/fetch endpoints, JavaScript URL, console errors и JWT-кандидаты.",
                    raw={"xhr_endpoints": len(endpoints), "javascript_urls": len(scripts),
                         "dom_xss_confirmed": len(confirmed), "screenshots": screenshots}))
