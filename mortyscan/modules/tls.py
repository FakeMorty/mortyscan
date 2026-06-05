"""Аудит TLS/SSL: версии протоколов, сертификат, истечение."""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "tls"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False

PROTOCOLS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1,   Severity.HIGH),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, Severity.HIGH),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, Severity.INFO),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, Severity.INFO),
]


def _probe(host: str, port: int, version: ssl.TLSVersion) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, AttributeError):
        return False
    try:
        with socket.create_connection((host, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _cert_info(host: str, port: int) -> dict | None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.getpeercert()
    except Exception:
        return None


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    host = ctx.target
    port = 443
    loop = asyncio.get_event_loop()

    # Поддержка протоколов
    results = await asyncio.gather(*[
        loop.run_in_executor(None, _probe, host, port, v) for _, v, _ in PROTOCOLS
    ])
    any_supported = False
    for (label, _, sev), supported in zip(PROTOCOLS, results):
        if not supported:
            continue
        any_supported = True
        if sev >= Severity.HIGH:
            ctx.add(Finding(
                module=NAME,
                title=f"Устаревший TLS поддерживается: {label}",
                severity=sev, cwe="CWE-327",
                description=f"Сервер всё ещё принимает соединения по {label}, "
                            "хотя этот протокол устарел и официально считается небезопасным.",
                remediation="Отключите TLS 1.0 и 1.1 в конфигурации сервера/балансировщика. "
                            "Оставьте только TLS 1.2 и TLS 1.3.",
            ))
        else:
            ctx.add(Finding(
                module=NAME, title=f"TLS поддерживается: {label}", severity=Severity.INFO,
            ))

    if not any_supported:
        ctx.add(Finding(module=NAME, title="HTTPS на порту 443 недоступен",
                        severity=Severity.INFO,
                        description="Возможно, сайт работает только по HTTP."))
        return

    # Сертификат
    cert = await loop.run_in_executor(None, _cert_info, host, port)
    if cert:
        try:
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=timezone.utc)
            days_left = (not_after - datetime.now(timezone.utc)).days
            sev = Severity.INFO
            if days_left < 0:    sev = Severity.HIGH
            elif days_left < 14: sev = Severity.MEDIUM
            elif days_left < 30: sev = Severity.LOW

            if days_left < 0:
                title = f"Сертификат ПРОСРОЧЕН ({-days_left} дн. назад)"
                desc = "Сертификат истёк. Браузеры показывают пользователям большое предупреждение."
                fix = "Срочно перевыпустите сертификат. Настройте автопродление через certbot/acme.sh."
            elif days_left < 30:
                title = f"Сертификат истекает через {days_left} дн."
                desc = "Скоро браузеры начнут показывать предупреждение об истёкшем сертификате."
                fix = "Перевыпустите заранее. Настройте автоматическое продление."
            else:
                title = f"Сертификат действителен ещё {days_left} дн."
                desc = ""
                fix = None

            ctx.add(Finding(
                module=NAME, title=title, severity=sev,
                description=desc + f" Кому выдан: {cert.get('subject')}. "
                                   f"Кем выдан: {cert.get('issuer')}. До: {cert['notAfter']}.",
                remediation=fix,
            ))
            sans = [v for k, v in cert.get("subjectAltName", []) if k.lower() == "dns"]
            if sans:
                ctx.add(Finding(
                    module=NAME,
                    title=f"Дополнительные имена в сертификате (SAN): {len(sans)} шт.",
                    severity=Severity.INFO,
                    description="Этот сертификат действителен ещё для:\n" +
                                "\n".join(f"  • {s}" for s in sans[:30]) +
                                ("\n  …" if len(sans) > 30 else ""),
                    raw={"sans": sans},
                ))
        except Exception as e:
            ctx.add(Finding(module=NAME, title="Не удалось разобрать сертификат",
                            description=str(e), severity=Severity.INFO))
