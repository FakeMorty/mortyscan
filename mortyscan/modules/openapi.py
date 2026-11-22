"""Scope-safe, read-only OpenAPI discovery and bounded GET contract probing."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from urllib.parse import quote, urljoin, urlparse, urlunparse

import httpx

from ..core import Finding, ScanContext, Severity, host_in_scope
from .crawler import _registrable

NAME = "openapi"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False
LOG = logging.getLogger("mortyscan.openapi")
MAX_SPEC_BYTES = 2 * 1024 * 1024
SPEC_PATHS = (
    "/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs",
    "/v3/api-docs", "/.well-known/openapi.json",
)
SAFE_METHODS = {"get", "head", "options"}


def _in_scope(ctx: ScanContext, url: str) -> bool:
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


def _safe_url(url: str) -> str:
    parsed = urlparse(url)
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


async def _read_limited(response: httpx.Response, limit: int) -> bytes:
    chunks = []
    total = 0
    async for chunk in response.aiter_bytes():
        if total >= limit:
            break
        part = chunk[:limit - total]
        chunks.append(part)
        total += len(part)
    return b"".join(chunks)


async def _probe(client: httpx.AsyncClient, method: str, url: str, *, params=None, headers=None, json_body=None):
    try:
        async with client.stream(method, url, params=params, headers=headers, json=json_body,
                                 follow_redirects=False) as response:
            body = await _read_limited(response, MAX_SPEC_BYTES)
            return response.status_code, body
    except Exception:
        return None


async def _fetch_spec(ctx: ScanContext, client: httpx.AsyncClient, url: str) -> dict | None:
    if not _in_scope(ctx, url):
        return None
    try:
        async with client.stream("GET", url, follow_redirects=False) as response:
            if response.status_code != 200:
                return None
            content = await _read_limited(response, MAX_SPEC_BYTES)
        data = json.loads(content.decode("utf-8", errors="strict"))
        if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
            return None
        if not (str(data.get("openapi", "")).startswith("3.") or str(data.get("swagger", "")) == "2.0"):
            return None
        return data
    except Exception:
        return None


def _document_urls(ctx: ScanContext) -> list[str]:
    candidates = [urljoin(ctx.base_url.rstrip("/") + "/", path.lstrip("/")) for path in SPEC_PATHS]
    for finding in ctx.findings:
        if finding.url and any(term in finding.title.lower() for term in ("openapi", "swagger", "спецификац")):
            candidates.append(_safe_url(finding.url))
    result = []
    seen = set()
    for url in candidates:
        safe = _safe_url(url)
        if safe not in seen and _in_scope(ctx, safe):
            seen.add(safe)
            result.append(url)
    return result[:20]


def _server_root(ctx: ScanContext, spec: dict, spec_url: str) -> str:
    servers = spec.get("servers") or []
    server_url = ""
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        server_url = str(servers[0].get("url") or "")
    if not server_url and spec.get("swagger") == "2.0":
        scheme = (spec.get("schemes") or [urlparse(ctx.base_url).scheme])[0]
        host = str(spec.get("host") or urlparse(ctx.base_url).netloc)
        server_url = f"{scheme}://{host}{spec.get('basePath') or '/'}"
    if not server_url:
        return ctx.base_url.rstrip("/") + "/"
    resolved = urljoin(spec_url, server_url)
    if not _in_scope(ctx, resolved):
        return ctx.base_url.rstrip("/") + "/"
    target = urlparse(ctx.base_url)
    server = urlparse(resolved)
    if server.username or server.password:
        return ctx.base_url.rstrip("/") + "/"
    if (target.scheme, target.hostname, target.port) != (server.scheme, server.hostname, server.port):
        return ctx.base_url.rstrip("/") + "/"
    if "{" in server.path or "}" in server.path:
        return ctx.base_url.rstrip("/") + "/"
    return resolved.rstrip("/") + "/"


def _parameter_values(spec: dict, path: str, operation: dict) -> tuple[dict[str, str], dict[str, str]]:
    path_item = spec.get("paths", {}).get(path, {})
    parameters = []
    for source in (path_item.get("parameters", []), operation.get("parameters", [])):
        if isinstance(source, list):
            parameters.extend(item for item in source if isinstance(item, dict))
    path_values: dict[str, str] = {}
    query_values: dict[str, str] = {}
    for param in parameters:
        name = str(param.get("name") or "")
        if not name or param.get("in") not in {"path", "query"}:
            continue
        schema = param.get("schema") if isinstance(param.get("schema"), dict) else {}
        value = param.get("example", schema.get("example", schema.get("default")))
        if value is None:
            enum = schema.get("enum")
            value = enum[0] if isinstance(enum, list) and enum else ("1" if param["in"] == "path" else "mortyscan_probe")
        target = path_values if param["in"] == "path" else query_values
        target[name] = str(value)[:200]
    for name in re.findall(r"\{([^{}]+)\}", path):
        path_values.setdefault(name, "1")
    return path_values, query_values


def _generated_cases(spec: dict, max_examples: int) -> tuple[list[dict], bool]:
    cases = []
    schemathesis_used = False
    try:
        import schemathesis
        loader = getattr(schemathesis, "from_dict", None)
        if loader is None:
            loader = schemathesis.openapi.from_dict
        schema = loader(spec)
        for result in schema.get_all_operations():
            if len(cases) >= max_examples:
                break
            try:
                operation = result.ok() if hasattr(result, "ok") else result
                method = str(operation.method).lower()
                if method not in SAFE_METHODS:
                    continue
                case = schema.get_case_strategy(operation).example()
                path_template = str(getattr(operation, "path", ""))
                operation_spec = operation.definition.raw if getattr(operation, "definition", None) else {}
                cases.append({"method": method.upper(), "path": case.formatted_path(),
                              "path_template": path_template,
                              "query": {str(k): str(v)[:200] for k, v in (case.query or {}).items()},
                              "operation_spec": operation_spec,
                              "security": operation_spec.get("security", spec.get("security"))})
                schemathesis_used = True
            except Exception:
                continue
    except ImportError:
        pass
    except Exception as exc:
        LOG.info("Schemathesis case generation unavailable: %s", type(exc).__name__)
    if not cases:
        for path, path_item in spec.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                if str(method).lower() not in SAFE_METHODS or not isinstance(operation, dict):
                    continue
                path_values, query_values = _parameter_values(spec, path, operation)
                rendered = str(path)
                for name, value in path_values.items():
                    rendered = rendered.replace("{" + name + "}", quote(value, safe=""))
                cases.append({"method": str(method).upper(), "path": rendered,
                              "path_template": str(path), "query": query_values,
                              "operation_spec": operation,
                              "security": operation.get("security", spec.get("security"))})
                if len(cases) >= max_examples:
                    return cases, False
    return cases[:max_examples], schemathesis_used


def _account_headers(ctx: ScanContext, account: str) -> dict[str, str]:
    state = ctx.auth.get(account, {}) if isinstance(ctx.auth, dict) else {}
    headers = {str(k): str(v) for k, v in (state.get("headers") or {}).items()}
    headers["Cookie"] = str(state.get("cookie") or "")
    return headers


def _is_protected(security) -> bool:
    return isinstance(security, list) and bool(security)


def _emit(ctx: ScanContext, title: str, severity: Severity, url: str, evidence: str,
          description: str, *, tags: list[str] | None = None) -> None:
    ctx.add(Finding(module=NAME, title=title, severity=severity, url=_safe_url(url),
                    evidence=evidence, description=description,
                    remediation="Сверьте API-политику с OpenAPI-контрактом и проверяйте авторизацию на сервере для каждого ресурса.",
                    source="OpenAPI safe probe", confidence="medium", tags=tags or ["openapi", "api"]))


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    if not ctx.config.get("openapi_enabled"):
        return
    if not ctx.permissions.get("intrusive"):
        ctx.add(Finding(module=NAME, title="OpenAPI-аудит пропущен: нет активного разрешения", severity=Severity.INFO,
                        source="permission gate", confidence="high"))
        return
    specs = []
    spec_url = ""
    for candidate in _document_urls(ctx):
        spec = await _fetch_spec(ctx, client, candidate)
        if spec:
            specs.append(spec)
            spec_url = candidate
            break
    if not specs:
        ctx.add(Finding(module=NAME, title="OpenAPI/Swagger спецификация не найдена",
                        severity=Severity.INFO,
                        description="Проверены стандартные same-scope пути и документы, найденные exposures.",
                        source="spec discovery", confidence="high"))
        return
    spec = specs[0]
    max_examples = 200 if ctx.config.get("aggressive") else 50
    cases, schemathesis_used = _generated_cases(spec, max_examples)
    api_root = _server_root(ctx, spec, spec_url)
    requests_sent = 0
    findings = 0
    rate_candidate = None
    account_a = _account_headers(ctx, "a")
    account_b = _account_headers(ctx, "b")
    has_b = bool(ctx.auth.get("b"))

    for case in cases:
        url = urljoin(api_root, str(case["path"]).lstrip("/"))
        if not _in_scope(ctx, url):
            continue
        parsed = urlparse(url)
        ctx.endpoints.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", "")))
        method = case["method"]
        operation_spec = case.get("operation_spec") if isinstance(case.get("operation_spec"), dict) else {}
        if not rate_candidate and ("/login" in parsed.path.lower() or "/api/" in parsed.path.lower()):
            rate_candidate = (url, method, case.get("query") or {})
        result = await _probe(client, method, url, params=case.get("query") or {})
        if result is None:
            continue
        status, body = result
        requests_sent += 1
        if status >= 500:
            findings += 1
            _emit(ctx, f"OpenAPI: серверная ошибка HTTP {status}", Severity.HIGH, url,
                  f"method={method}; status={status}; response_sha256={hashlib.sha256(body).hexdigest()}",
                  "Read-only schema probe вызвал server error. Содержимое ответа не сохраняется.", tags=["openapi", "server-error"])
        expected_responses = operation_spec.get("responses", {})
        if isinstance(expected_responses, dict) and expected_responses:
            status_keys = {str(code).upper() for code in expected_responses}
            declared = (str(status) in status_keys or "DEFAULT" in status_keys
                        or f"{status // 100}XX" in status_keys)
            if not declared:
                findings += 1
                _emit(ctx, f"OpenAPI: HTTP {status} не описан контрактом", Severity.MEDIUM, url,
                      f"method={method}; status={status}; declared_responses={','.join(sorted(status_keys)[:20])}",
                      "Ответ не совпал со списком статус-кодов в OpenAPI. Содержимое ответа не сохранялось.",
                      tags=["openapi", "contract-violation"])
        if method == "GET" and _is_protected(case.get("security")):
            anonymous = await _probe(client, "GET", url, params=case.get("query") or {},
                                     headers={"Authorization": "", "Cookie": ""})
            if anonymous:
                requests_sent += 1
                anonymous_status, anonymous_body = anonymous
                if anonymous_status == 200:
                    findings += 1
                    _emit(ctx, "OpenAPI: возможен auth bypass на защищённом endpoint", Severity.CRITICAL, url,
                          f"method=GET; anonymous_status=200; response_sha256={hashlib.sha256(anonymous_body).hexdigest()}",
                          "OpenAPI объявляет endpoint защищённым, но запрос без Authorization/Cookie получил 200.",
                          tags=["openapi", "auth-bypass"])
        path_template = str(case.get("path_template") or case.get("path", ""))
        path_values, _ = _parameter_values(spec, path_template, operation_spec)
        if method == "GET" and path_values and has_b:
            response_a = await _probe(client, "GET", url, params=case.get("query") or {}, headers=account_a)
            response_b = await _probe(client, "GET", url, params=case.get("query") or {}, headers=account_b)
            requests_sent += int(response_a is not None) + int(response_b is not None)
            if response_a and response_b:
                status_a, body_a = response_a
                status_b, body_b = response_b
                hash_a = hashlib.sha256(body_a).hexdigest()
                hash_b = hashlib.sha256(body_b).hexdigest()
                if (status_a == 200 and status_b == 200 and hash_a == hash_b
                        and len(body_a) < MAX_SPEC_BYTES and len(body_b) < MAX_SPEC_BYTES):
                    findings += 1
                    _emit(ctx, "Возможный BOLA/IDOR: аккаунт B прочитал ресурс аккаунта A", Severity.CRITICAL, url,
                          f"account_a_status=200; account_b_status=200; body_sha256={hash_a}",
                          "Один и тот же path-ID вернул аккаунту B тот же ответ, что аккаунту A. В теле ответа данные не сохранялись.",
                          tags=["openapi", "bola", "idor"])

    if rate_candidate:
        url, method, query = rate_candidate
        statuses = []
        for _ in range(20):
            response = await _probe(client, "GET", url, params=query)
            if response is None:
                break
            status, _body = response
            statuses.append(status)
            requests_sent += 1
            if status == 429:
                break
        if len(statuses) == 20 and 429 not in statuses:
            _emit(ctx, "OpenAPI: rate limit не обнаружен на API/login GET", Severity.LOW, url,
                  "20 idempotent GET запросов не получили HTTP 429; это не доказывает отсутствие лимитов на другие клиенты.",
                  "Повторены только GET-запросы; POST/login формы не отправлялись.", tags=["openapi", "rate-limit"])

    ctx.add(Finding(module=NAME, title=f"OpenAPI-аудит завершён: safe cases {len(cases)}",
                    severity=Severity.INFO,
                    description="Схема проверена bounded read-only GET/HEAD/OPTIONS запросами. POST/PUT/PATCH/DELETE и mass assignment не отправлялись.",
                    source="Schemathesis" if schemathesis_used else "built-in OpenAPI parser",
                    confidence="medium",
                    raw={"spec_url": _safe_url(spec_url), "schema_paths": len(spec.get("paths", {})),
                         "safe_cases": len(cases), "requests_sent": requests_sent,
                         "schemathesis_used": schemathesis_used, "max_examples": max_examples,
                         "findings": findings, "write_tests": False}))
