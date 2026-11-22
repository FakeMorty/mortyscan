"""Opt-in deep TLS checks through the optional SSLyze Python package."""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from ..core import Finding, ScanContext, Severity, host_in_scope

NAME = "tls_deep"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False
LOG = logging.getLogger("mortyscan.tls_deep")


def _attempt(scan_result, attribute: str):
    attempts = getattr(scan_result, "scan_result", None)
    attempt = getattr(attempts, attribute, None) if attempts is not None else None
    if not attempt:
        return None
    status = getattr(getattr(attempt, "status", None), "value", getattr(attempt, "status", None))
    return getattr(attempt, "result", None) if status == "COMPLETED" else None


def _emit(ctx: ScanContext, title: str, severity: Severity, *, evidence: str = "", cvss: float | None = None,
          remediation: str = "Обновите TLS stack и повторите проверку; отключите устаревшие протоколы и слабые наборы шифров.") -> None:
    ctx.add(Finding(module=NAME, title=title, severity=severity, cwe="CWE-326",
                    cvss=cvss, evidence=evidence[:1000], remediation=remediation,
                    source="SSLyze", confidence="high", tags=["tls", "sslyze"]))


def _consume_result(ctx: ScanContext, scan_result) -> int:
    if getattr(scan_result, "scan_result", None) is None:
        return 0
    count = 0
    for attribute, label in (("ssl_2_0_cipher_suites", "SSL 2.0"),
                             ("ssl_3_0_cipher_suites", "SSL 3.0"),
                             ("tls_1_0_cipher_suites", "TLS 1.0"),
                             ("tls_1_1_cipher_suites", "TLS 1.1"),
                             ("tls_1_2_cipher_suites", "TLS 1.2"),
                             ("tls_1_3_cipher_suites", "TLS 1.3")):
        result = _attempt(scan_result, attribute)
        if not result:
            continue
        if getattr(result, "is_tls_version_supported", False) and label in {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}:
            poodle = label == "SSL 3.0"
            _emit(ctx, f"Устаревший протокол {label} поддерживается" + (" (POODLE-риск)" if poodle else ""),
                  Severity.HIGH if poodle else Severity.MEDIUM,
                  evidence=f"protocol={label}; accepted_cipher_count={len(result.accepted_cipher_suites)}",
                  cvss=5.0 if poodle else 5.3)
            count += 1
        weak = []
        export_ciphers = []
        for accepted in getattr(result, "accepted_cipher_suites", []) or []:
            suite = getattr(accepted, "cipher_suite", None)
            if not suite:
                continue
            name = str(getattr(suite, "name", "unknown"))
            key_size = int(getattr(suite, "key_size", 0) or 0)
            if key_size < 128:
                weak.append(f"{name} ({key_size}-bit)")
            if "EXPORT" in name.upper():
                export_ciphers.append(name)
        if weak:
            _emit(ctx, f"TLS {label}: слабые шифры (<128 бит)", Severity.MEDIUM,
                  evidence="accepted=" + ", ".join(sorted(set(weak))[:20]), cvss=5.3)
            count += 1
        if export_ciphers:
            is_freak = any("RSA" in name.upper() for name in export_ciphers)
            vuln_name = "FREAK" if is_freak else "Logjam"
            _emit(ctx, f"TLS: export cipher suites указывают на риск {vuln_name}", Severity.HIGH,
                  evidence="accepted=" + ", ".join(sorted(set(export_ciphers))[:20]), cvss=7.4)
            count += 1

    heartbleed = _attempt(scan_result, "heartbleed")
    if heartbleed and getattr(heartbleed, "is_vulnerable_to_heartbleed", False):
        _emit(ctx, "TLS: подтверждён Heartbleed", Severity.HIGH, evidence="SSLyze heartbleed probe: vulnerable",
              cvss=7.5, remediation="Обновите OpenSSL немедленно, перезапустите сервисы и смените потенциально раскрытые секреты.")
        count += 1
    robot = _attempt(scan_result, "robot")
    if robot:
        status = str(getattr(robot, "robot_result", ""))
        if "VULNERABLE_STRONG_ORACLE" in status:
            _emit(ctx, "TLS: ROBOT — сильный RSA padding oracle", Severity.HIGH, evidence=status, cvss=7.5)
            count += 1
        elif "VULNERABLE_WEAK_ORACLE" in status:
            _emit(ctx, "TLS: ROBOT — слабый RSA padding oracle", Severity.MEDIUM, evidence=status, cvss=5.0)
            count += 1

    cert_result = _attempt(scan_result, "certificate_info")
    if cert_result:
        for deployment in (getattr(cert_result, "certificate_deployments", []) or [])[:4]:
            chain = getattr(deployment, "received_certificate_chain", []) or []
            if not chain:
                continue
            leaf = chain[0]
            not_after = getattr(leaf, "not_valid_after_utc", None)
            if not_after is None:
                not_after = getattr(leaf, "not_valid_after", None)
                if not_after and not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
            if not_after:
                days_left = (not_after - datetime.now(timezone.utc)).days
                if days_left < 0:
                    _emit(ctx, "TLS certificate is expired", Severity.HIGH,
                          evidence=f"days_expired={abs(days_left)}; certificate_count={len(chain)}", cvss=7.4)
                    count += 1
            validations = getattr(deployment, "path_validation_results", []) or []
            if validations and not any(getattr(item, "was_validation_successful", False) for item in validations):
                _emit(ctx, "TLS certificate chain validation failed", Severity.MEDIUM,
                      evidence=f"received_chain_count={len(chain)}; trust_store_checks={len(validations)}", cvss=5.3)
                count += 1
            ocsp_response = getattr(deployment, "ocsp_response", None)
            must_staple = bool(getattr(deployment, "leaf_certificate_has_must_staple_extension", False))
            if must_staple and ocsp_response is None:
                _emit(ctx, "TLS OCSP Must-Staple extension lacks a stapled response", Severity.MEDIUM,
                      evidence="must_staple=true; stapled_response=false", cvss=6.5)
                count += 1
            elif ocsp_response is not None and getattr(deployment, "ocsp_response_is_trusted", None) is False:
                _emit(ctx, "TLS stapled OCSP response is untrusted", Severity.MEDIUM,
                      evidence="ocsp_response_trusted=false", cvss=5.3)
                count += 1

    headers_result = _attempt(scan_result, "http_headers")
    if headers_result and getattr(headers_result, "strict_transport_security_header", None) is None:
        _emit(ctx, "TLS: HTTPS response lacks HSTS", Severity.LOW,
              evidence="strict-transport-security header not observed", cvss=3.1,
              remediation="Добавьте Strict-Transport-Security после проверки всех поддоменов и HTTPS-конфигурации.")
        count += 1
    return count


def _scan_sync(host: str, port: int, ip: str, proxy_url: str = ""):
    from sslyze import (HttpProxySettings, ScanCommand, Scanner, ServerNetworkConfiguration,
                        ServerNetworkLocation, ServerScanRequest)
    commands = {
        ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES, ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES, ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES, ScanCommand.HEARTBLEED,
        ScanCommand.ROBOT, ScanCommand.HTTP_HEADERS,
    }
    if proxy_url:
        proxy_settings = HttpProxySettings.from_url(proxy_url)
        location = ServerNetworkLocation(hostname=host, port=port, http_proxy_settings=proxy_settings)
    else:
        location = ServerNetworkLocation(hostname=host, port=port, ip_address=ip or None)
    network = ServerNetworkConfiguration.default_for_server_location(location)
    from dataclasses import replace
    network = replace(network, network_timeout=3, network_max_retries=0)
    request = ServerScanRequest(server_location=location, network_configuration=network, scan_commands=commands)
    scanner = Scanner(per_server_concurrent_connections_limit=2, concurrent_server_scans_limit=1)
    scanner.queue_scans([request])
    return list(scanner.get_results())


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    del client
    if not ctx.config.get("tls_deep_enabled"):
        return
    if not ctx.permissions.get("intrusive"):
        ctx.add(Finding(module=NAME, title="Глубокий TLS-аудит пропущен: требуется активное разрешение",
                        severity=Severity.INFO, source="permission gate", confidence="high"))
        return
    if ctx.config.get("no_external"):
        ctx.add(Finding(module=NAME, title="Глубокий TLS-аудит пропущен (--no-external)",
                        severity=Severity.INFO, source="operator option", confidence="high"))
        return
    parsed = urlparse(ctx.base_url)
    scope_hosts = set(ctx.config.get("scope_hosts", []))
    if scope_hosts and not host_in_scope(parsed.hostname or "", scope_hosts):
        ctx.add(Finding(module=NAME, title="Глубокий TLS-аудит пропущен: хост вне scope",
                        severity=Severity.INFO, source="scope enforcement", confidence="high"))
        return
    if parsed.scheme != "https":
        ctx.add(Finding(module=NAME, title="Глубокий TLS-аудит пропущен: цель использует не HTTPS",
                        severity=Severity.INFO, source="protocol gate", confidence="high"))
        return
    try:
        import sslyze  # noqa: F401
    except ImportError:
        ctx.add(Finding(module=NAME, title="SSLyze не установлен — глубокий TLS-аудит пропущен",
                        severity=Severity.INFO, description="Установите optional extra `pip install -e '.[tls]'`.",
                        source="optional dependency", confidence="high"))
        return
    host = parsed.hostname or ctx.target
    port = parsed.port or 443
    timeout = max(15, min(180, int(ctx.config.get("tls_deep_timeout", 120))))
    LOG.warning("SSLyze deep TLS scan explicitly enabled for %s:%s", host, port)
    try:
        results = await asyncio.wait_for(
            asyncio.to_thread(_scan_sync, host, port, ctx.ip or "", str(ctx.config.get("proxy") or "")),
            timeout=timeout)
    except asyncio.TimeoutError:
        ctx.add(Finding(module=NAME, title="SSLyze остановлен по таймауту", severity=Severity.INFO,
                        description=f"Сетевые таймауты проверки ограничены 3 секундами; общий лимит {timeout} секунд.",
                        source="scan timeout", confidence="high"))
        return
    except Exception as exc:
        LOG.warning("SSLyze scan failed (%s)", type(exc).__name__)
        ctx.add(Finding(module=NAME, title="Глубокий TLS-аудит не завершён", severity=Severity.INFO,
                        description=f"SSLyze завершился с ошибкой {type(exc).__name__}; исключение не раскрывает сетевые данные.",
                        source="SSLyze", confidence="high"))
        return
    findings = sum(_consume_result(ctx, result) for result in results)
    ctx.add(Finding(module=NAME, title=f"Глубокий TLS-аудит завершён: проблем {findings}", severity=Severity.INFO,
                    source="SSLyze", confidence="high",
                    raw={"host": host, "port": port, "findings": findings,
                         "commands": 10, "network_timeout_seconds": 3,
                         "proxy_used": bool(ctx.config.get("proxy"))}))
