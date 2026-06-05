"""Аудит JWT-токенов, найденных крауlером в cookies/ответах."""
from __future__ import annotations

import base64
import json
import re
from typing import Iterable

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "jwt"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

# Топ-100 самых популярных «секретов» из реальных утечек
WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "jwt_secret", "your-256-bit-secret",
    "your_jwt_secret", "supersecret", "secretkey", "mysecret", "test", "dev",
    "qwerty", "abc123", "letmein", "changeme", "default", "JWT_SECRET",
    "asdf", "1234", "0000", "secret123", "MIIEpAIBAAKCAQEA",
]


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _parse_jwt(tok: str) -> tuple[dict, dict, bytes] | None:
    try:
        h, p, sig = tok.split(".")
        header = json.loads(_b64url_decode(h))
        payload = json.loads(_b64url_decode(p))
        signature = _b64url_decode(sig) if sig else b""
        return header, payload, signature
    except Exception:
        return None


def _crack_hs256(message: bytes, sig: bytes) -> str | None:
    """Брутфорс HS256 по короткому словарю."""
    import hmac, hashlib
    for s in WEAK_SECRETS:
        expected = hmac.new(s.encode(), message, hashlib.sha256).digest()
        if hmac.compare_digest(expected, sig):
            return s
    return None


def _collect_tokens(ctx: ScanContext) -> Iterable[tuple[str, str]]:
    """Источник токенов: cookies/ответы крауlера. Сейчас — ищем в headers и context.config."""
    seen: set[str] = set()
    # Из всех захваченных заголовков
    for v in ctx.headers.values():
        for m in JWT_RE.findall(v):
            if m not in seen:
                seen.add(m); yield ("headers", m)
    # Если кто-то положил в config
    for tok in ctx.config.get("seen_jwts", []) or []:
        if tok not in seen:
            seen.add(tok); yield ("crawler", tok)


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    tokens = list(_collect_tokens(ctx))
    if not tokens:
        return

    for source, tok in tokens:
        parsed = _parse_jwt(tok)
        if not parsed:
            continue
        header, payload, sig = parsed
        alg = (header.get("alg") or "").lower()

        # alg=none
        if alg == "none":
            ctx.add(Finding(
                module=NAME,
                title="JWT: разрешён небезопасный alg=none",
                severity=Severity.CRITICAL, cwe="CWE-347", cvss=9.8,
                evidence=f"источник: {source}; header={header}",
                description="Найден JWT с alg=none. Если валидатор такие токены принимает — "
                            "любой может подделать токен от чьего угодно имени без всякой подписи.",
                remediation="На стороне валидатора явно запретите alg=none. "
                            "Лучше — перейти на RS256/ES256 (асимметричная криптография).",
            ))
            continue

        # HS256 — попытка подобрать слабый секрет
        if alg == "hs256" and sig:
            message = tok.rsplit(".", 1)[0].encode()
            secret = _crack_hs256(message, sig)
            if secret:
                ctx.add(Finding(
                    module=NAME,
                    title=f"JWT: HS256 подписан слабым секретом «{secret}»",
                    severity=Severity.CRITICAL, cwe="CWE-326", cvss=9.8,
                    evidence=f"токен начинается с {tok[:30]}…",
                    description="Удалось подобрать секрет JWT по короткому словарю. "
                                "Атакующий может выпустить токен от имени любого пользователя.",
                    remediation="Сгенерируйте новый случайный секрет (≥256 бит). "
                                "Лучше — переходите на RS256/ES256.",
                ))
            else:
                ctx.add(Finding(
                    module=NAME,
                    title="JWT с HS256 (секрет в коротком словаре не найден)",
                    severity=Severity.LOW,
                    description="Используется симметричный алгоритм HS256. "
                                "Если секрет утечёт — все токены можно подделывать. "
                                "Рекомендуется переходить на RS256/ES256.",
                    remediation="Используйте асимметричные алгоритмы и храните приватный ключ в vault.",
                ))

        # Просрочка
        exp = payload.get("exp")
        if exp:
            import time as _t
            if exp < _t.time() - 86400:
                ctx.add(Finding(
                    module=NAME,
                    title="JWT просрочен более чем на сутки",
                    severity=Severity.INFO,
                    description=f"exp={exp}. Проверьте, что сервер действительно отвергает просроченные токены.",
                ))

        # Информация о токене
        ctx.add(Finding(
            module=NAME,
            title=f"Обнаружен JWT (алгоритм {alg.upper() or '?'})",
            severity=Severity.INFO,
            description=f"Заголовок: {header}\nПолезная нагрузка: "
                        f"{json.dumps(payload, ensure_ascii=False)[:400]}",
        ))
