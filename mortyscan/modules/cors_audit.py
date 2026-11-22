"""Активная, низкоинтенсивная проверка CORS известных endpoint'ов.

Только GET/OPTIONS, без изменяющих состояние запросов и без переходов по редиректам.
Настроенная аутентификация применяется только к target origin.
"""
from __future__ import annotations

import asyncio
import ipaddress
import time
from urllib.parse import urlparse, urlunsplit

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "cors_audit"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False
PROBE_ORIGIN = "https://mortyscan-audit.invalid"
MAX_ENDPOINTS = 12


class _RateGate:
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


def _same_host(url: str, target: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in {"http", "https"} and parsed.hostname == target
    except Exception:
        return False


def _urls(ctx: ScanContext) -> list[str]:
    candidates = [ctx.base_url, *sorted(ctx.endpoints), *sorted(ctx.crawled_urls)]
    seen: set[str] = set()
    selected: list[str] = []
    limit = min(MAX_ENDPOINTS, max(1, int(ctx.config.get("cors_max_endpoints", MAX_ENDPOINTS))))
    for url in candidates:
        if not _same_host(url, ctx.target):
            continue
        parsed = urlparse(url)
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        if url in seen:
            continue
        seen.add(url)
        selected.append(url)
        if len(selected) >= limit:
            break
    return selected


def _origins(ctx: ScanContext) -> list[tuple[str, str]]:
    # Reserved domains prevent probes from reaching third-party systems.
    host = ctx.target.lower().strip("[]")
    values = [(PROBE_ORIGIN, "arbitrary") , ("null", "null")]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        values.extend([
            (f"https://{host}.evil.invalid", "suffix-bypass"),
            (f"https://unlisted.{host}", "unlisted-subdomain"),
        ])
    return values


def _emit(ctx: ScanContext, url: str, origin: str, case: str, allow_credentials: str,
          *, preflight: bool = False, evidence_extra: str = "") -> None:
    if case == "wildcard-credentials":
        title = "CORS: wildcard сочетается с credentials"
        severity = Severity.MEDIUM
        explanation = ("Сочетание ACAO=* и credentials=true некорректно: современные браузеры блокируют "
                       "такой credentialed CORS-ответ. Это мисконфигурация, но не подтверждение обхода браузерной защиты.")
    elif case == "null":
        title = "CORS доверяет Origin: null"
        severity = Severity.HIGH if allow_credentials == "true" else Severity.MEDIUM
        explanation = "Origin null может появляться у sandboxed/локальных документов; не разрешайте его для приватных ответов."
    elif case == "suffix-bypass":
        title = "CORS отражает Origin с добавленным недоверенным доменом"
        severity = Severity.HIGH if allow_credentials == "true" else Severity.MEDIUM
        explanation = "Отражён Origin, у которого целевой hostname помещён в имя чужого домена — признак небезопасной проверки по подстроке/суффиксу."
    elif case == "unlisted-subdomain":
        title = "CORS доверяет непроверенному поддомену"
        severity = Severity.MEDIUM if allow_credentials == "true" else Severity.LOW
        explanation = "Политика разрешила поддомен, который не входит в текущий список просканированных хостов. Проверьте, контролируете ли вы его и защищены ли от takeover."
    else:
        title = ("CORS preflight разрешает произвольный Origin с credentials" if preflight
                 else "CORS доверяет произвольному Origin с credentials") if allow_credentials == "true" else "CORS отражает произвольный Origin"
        severity = Severity.HIGH if allow_credentials == "true" else Severity.LOW
        explanation = ("Проверочный Origin отражён сервером. При credentials=true это может позволить чужому сайту читать "
                       "ответ от имени пользователя, если браузерный запрос допустим." if allow_credentials == "true" else
                       "Проверочный Origin отражён, но credentials не разрешены; оцените, не раскрывает ли endpoint непубличные данные.")
    if preflight and severity > Severity.MEDIUM:
        severity = Severity.MEDIUM
    ctx.add(Finding(
        module=NAME, title=title, severity=severity, cwe="CWE-942", url=url,
        evidence=f"Origin={origin}; ACAO={evidence_extra}; ACAC={allow_credentials or '(нет)'}" + ("; OPTIONS-preflight" if preflight else ""),
        description=explanation,
        remediation="Разрешайте только точные доверенные Origins (схема, hostname и порт). Не используйте отражение, wildcard с credentials или проверки по подстроке.",
        source="CORS response", confidence="high" if allow_credentials == "true" else "medium",
        tags=["cors", "active-probe"],
    ))


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    urls = _urls(ctx)
    if not urls:
        return
    gate = _RateGate(float(ctx.config.get("rate_limit", 10.0)),
                     enabled=not ctx.config.get("_client_rate_limited", False))
    probes = _origins(ctx)
    checked = 0
    for url in urls:
        for origin, case in probes:
            await gate.wait()
            try:
                response = await client.get(url, headers={"Origin": origin}, follow_redirects=False)
            except Exception:
                continue
            checked += 1
            allow_origin = response.headers.get("access-control-allow-origin", "").strip()
            allow_credentials = response.headers.get("access-control-allow-credentials", "").strip().lower()
            if allow_origin == "*" and allow_credentials == "true":
                _emit(ctx, url, origin, "wildcard-credentials", allow_credentials, evidence_extra="*")
            elif allow_origin == origin:
                _emit(ctx, url, origin, case, allow_credentials, evidence_extra=allow_origin)

        # Одно безопасное GET preflight на endpoint, без тела и без изменяющего состояние метода.
        await gate.wait()
        try:
            preflight = await client.options(
                url, follow_redirects=False,
                headers={
                    "Origin": PROBE_ORIGIN,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "X-MortyScan-Probe",
                },
            )
        except Exception:
            continue
        checked += 1
        preflight_origin = preflight.headers.get("access-control-allow-origin", "").strip()
        preflight_credentials = preflight.headers.get("access-control-allow-credentials", "").strip().lower()
        if preflight_origin == PROBE_ORIGIN and preflight_credentials == "true":
            extra = (f"{preflight_origin}; ACAM="
                     f"{preflight.headers.get('access-control-allow-methods', '')[:100]}; ACAH="
                     f"{preflight.headers.get('access-control-allow-headers', '')[:100]}")
            _emit(ctx, url, PROBE_ORIGIN, "arbitrary", preflight_credentials,
                  preflight=True, evidence_extra=extra)

    ctx.add(Finding(
        module=NAME, title=f"Проверка CORS завершена: endpoint'ов {len(urls)}",
        severity=Severity.INFO,
        description="Проверены ответы с несколькими посторонними Origin и безопасные OPTIONS-preflight. "
                    "Изменяющие состояние запросы не отправлялись; заданная аутентификация использовалась только на target origin.",
        raw={"endpoints": urls, "requests_sent": checked, "probe_origin": PROBE_ORIGIN},
    ))
