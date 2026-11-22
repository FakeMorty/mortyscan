"""Explicit form-login bootstrap for API scans; credentials remain memory-only."""
from __future__ import annotations

import logging
import re
from http.cookiejar import Cookie
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ..core import Finding, ScanContext, Severity, host_in_scope
from .crawler import _registrable

NAME = "auth"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False
LOG = logging.getLogger("mortyscan.auth")

_USER_RE = re.compile(r"user|email|login|account", re.I)
_PASS_RE = re.compile(r"pass|pwd", re.I)
_TOKEN_KEYS = {"access_token", "token", "id_token", "jwt", "authorization"}


def _in_scope(ctx: ScanContext, url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    scope = set(ctx.config.get("scope_hosts", []))
    if scope:
        return host_in_scope(parsed.hostname, scope)
    return _registrable(parsed.hostname) == _registrable(ctx.target)


def _parse_credentials(value: str) -> tuple[str, str] | None:
    user, separator, password = value.partition(":")
    if not separator or not user or not password:
        return None
    return user, password


def _extract_token(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in _TOKEN_KEYS and isinstance(item, str) and item:
                return item
        for item in value.values():
            result = _extract_token(item)
            if result:
                return result
    elif isinstance(value, list):
        for item in value:
            result = _extract_token(item)
            if result:
                return result
    return ""


def _cookie_header(client: httpx.AsyncClient, target_host: str, initial: str = "") -> str:
    values = {}
    for part in initial.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name:
            values[name] = value
    try:
        for cookie in client.cookies.jar:
            domain = (cookie.domain or "").lstrip(".").lower()
            host = target_host.lower().rstrip(".")
            if domain and (host == domain or host.endswith("." + domain)):
                values[cookie.name] = cookie.value
    except Exception:
        pass
    return "; ".join(f"{name}={value}" for name, value in values.items())


def _form_data(page_html: str, login_url: str, user: str, password: str) -> tuple[str, dict[str, str]] | None:
    soup = BeautifulSoup(page_html, "html.parser")
    form = next((candidate for candidate in soup.find_all("form")
                 if (candidate.get("method") or "get").lower() == "post"), None)
    if form is None:
        return None
    action = urljoin(login_url, str(form.get("action") or login_url))
    fields: dict[str, str] = {}
    user_field = pass_field = ""
    for field in form.find_all(["input", "textarea"]):
        name = str(field.get("name") or "").strip()
        if not name:
            continue
        field_type = str(field.get("type") or "text").lower()
        if field_type == "hidden":
            fields[name] = str(field.get("value") or "")
        elif field_type in {"password", "text", "email"}:
            if not user_field and field_type != "password" and _USER_RE.search(name):
                user_field = name
            if not pass_field and (field_type == "password" or _PASS_RE.search(name)):
                pass_field = name
    if not user_field:
        user_field = "username"
    if not pass_field:
        pass_field = "password"
    fields[user_field] = user
    fields[pass_field] = password
    return action, fields


def _snapshot_cookies(client: httpx.AsyncClient) -> list[Cookie]:
    try:
        return list(client.cookies.jar)
    except Exception:
        return []


def _restore_baseline(client: httpx.AsyncClient, headers: dict[str, str], cookies: list[Cookie]) -> None:
    client.headers.clear()
    client.headers.update(headers)
    client.cookies = httpx.Cookies()
    for cookie in cookies:
        try:
            client.cookies.jar.set_cookie(cookie)
        except Exception:
            continue


async def _login(ctx: ScanContext, client: httpx.AsyncClient, label: str,
                 login_url: str, credentials: str, *, initial_cookie: str = "") -> dict | None:
    parsed_login = urlparse(login_url)
    if not _in_scope(ctx, login_url):
        ctx.add(Finding(module=NAME, title=f"Вход аккаунта {label.upper()} пропущен: login URL вне scope",
                        severity=Severity.INFO, url=login_url,
                        source="scope enforcement", confidence="high"))
        return None
    parsed_base = urlparse(ctx.base_url)
    if parsed_login.scheme != parsed_base.scheme or parsed_login.hostname != parsed_base.hostname or parsed_login.port != parsed_base.port:
        ctx.add(Finding(module=NAME, title=f"Вход аккаунта {label.upper()} пропущен: другой origin",
                        severity=Severity.INFO, url=login_url,
                        description="Передача login credentials разрешается только на точный origin целевого сайта.",
                        source="credential origin gate", confidence="high"))
        return None
    parsed_credentials = _parse_credentials(credentials)
    if not parsed_credentials:
        ctx.add(Finding(module=NAME, title=f"Некорректный формат credentials аккаунта {label.upper()}",
                        severity=Severity.LOW, description="Ожидается формат user:pass; значение не сохранялось в отчёт.",
                        source="CLI validation", confidence="high"))
        return None
    username, password = parsed_credentials
    try:
        page = await client.get(login_url)
        if page.status_code >= 400:
            raise ValueError(f"login page HTTP {page.status_code}")
        form = _form_data(page.text, str(page.url), username, password)
        if not form:
            raise ValueError("POST login form not found")
        action, data = form
        parsed_action = urlparse(action)
        if (not _in_scope(ctx, action) or parsed_action.scheme != parsed_login.scheme
                or parsed_action.hostname != parsed_login.hostname or parsed_action.port != parsed_login.port):
            raise ValueError("login form action is outside login origin/scope")
        response = await client.post(action, data=data)
        token = ""
        try:
            token = _extract_token(response.json())
        except Exception:
            pass
        token = token or response.headers.get("authorization", "")
        headers = {name: value for name, value in client.headers.items()
                   if name.lower() not in {"cookie", "host", "content-length"}}
        if token:
            headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
        cookie = _cookie_header(client, ctx.target, initial_cookie)
        if cookie:
            client.headers["Cookie"] = cookie
        for name, value in headers.items():
            client.headers[name] = value
        state = {"cookie": cookie, "headers": headers}
        # Validate the newly established session without recording response contents.
        valid = False
        for path in ("/", "/profile"):
            try:
                check = await client.get(urljoin(ctx.base_url.rstrip("/") + "/", path.lstrip("/")))
            except Exception:
                continue
            if check.status_code == 200 and "login" not in urlparse(str(check.url)).path.lower():
                valid = True
                break
        if not valid:
            ctx.add(Finding(module=NAME, title=f"Сессия аккаунта {label.upper()} не подтверждена",
                            severity=Severity.LOW, description="После POST не удалось подтвердить HTTP 200 на / или /profile вне login URL.",
                            source="login validation", confidence="medium"))
            return None
        ctx.add(Finding(module=NAME, title=f"Вход аккаунта {label.upper()} выполнен",
                        severity=Severity.INFO, description="Сессия проверена запросом к / или /profile; credential-значения не сохранялись в отчёте.",
                        source="form login", confidence="high"))
        return state
    except Exception as exc:
        LOG.warning("login failed for account %s (%s)", label, type(exc).__name__)
        ctx.add(Finding(module=NAME, title=f"Не удалось выполнить вход аккаунта {label.upper()}",
                        severity=Severity.LOW,
                        description=f"Ошибка: {type(exc).__name__}; тело ответа и credentials не записывались.",
                        source="form login", confidence="high"))
        return None


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    baseline_headers = dict(client.headers)
    baseline_cookies = _snapshot_cookies(client)
    baseline_cookie = str(ctx.config.get("cookie") or client.headers.get("cookie", ""))
    state_a = {"cookie": _cookie_header(client, ctx.target, baseline_cookie),
               "headers": {key: value for key, value in baseline_headers.items()
                           if key.lower() not in {"cookie", "host", "content-length"}}}
    ctx.auth = {"a": state_a}
    login_url = str(ctx.config.get("login_url") or "").strip()
    login_creds = str(ctx.config.get("login_creds") or "")
    account_b = str(ctx.config.get("account_b") or "")
    if login_url and login_creds:
        logged_in_a = await _login(ctx, client, "a", login_url, login_creds,
                                   initial_cookie=baseline_cookie)
        if logged_in_a:
            state_a = logged_in_a
            ctx.auth["a"] = state_a
    if account_b:
        if not login_url:
            ctx.add(Finding(module=NAME, title="Аккаунт B пропущен: требуется --login-url",
                            severity=Severity.INFO, source="configuration gate", confidence="high"))
        else:
            _restore_baseline(client, baseline_headers, baseline_cookies)
            client.headers.pop("Cookie", None)
            client.headers.pop("Authorization", None)
            client.cookies = httpx.Cookies()
            state_b = await _login(ctx, client, "b", login_url, account_b)
            if state_b:
                ctx.auth["b"] = state_b
    # Keep the primary session for all regular scanner modules; B remains isolated as data only.
    _restore_baseline(client, baseline_headers, baseline_cookies)
    if state_a.get("cookie"):
        client.headers["Cookie"] = state_a["cookie"]
    for name, value in state_a.get("headers", {}).items():
        client.headers[name] = value
    if state_a.get("cookie"):
        ctx.config["cookie"] = state_a["cookie"]
    authorization = next((value for key, value in state_a.get("headers", {}).items()
                          if key.lower() == "authorization"), "")
    if authorization:
        headers = [str(value) for value in ctx.config.get("request_headers", [])
                   if str(value).partition(":")[0].strip().lower() != "authorization"]
        headers.append(f"Authorization: {authorization}")
        ctx.config["request_headers"] = headers
    ctx.config.pop("login_creds", None)
    ctx.config.pop("account_b", None)
