"""Подбор скрытых путей со списком слов и грамотной обработкой soft-404."""
from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import urljoin

import httpx

from ..core import Finding, ScanContext, Severity, page_signature, rand_str, similarity

NAME = "discovery"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False


async def _baseline(client: httpx.AsyncClient, base: str) -> dict:
    probes = []
    for _ in range(3):
        p = f"/{rand_str(16)}/{rand_str(8)}.{rand_str(3)}"
        try:
            r = await client.get(urljoin(base, p))
            probes.append({
                "status": r.status_code,
                "sig": page_signature(r.text),
                "loc": r.headers.get("location", ""),
            })
        except Exception:
            pass
    return {"probes": probes}


def _looks_like_baseline(resp_status: int, sig: dict, loc: str, baseline: dict) -> bool:
    for p in baseline.get("probes", []):
        if p["status"] == resp_status and similarity(sig, p["sig"], tol=0.10):
            return True
        if loc and p.get("loc") and loc == p["loc"]:
            return True
    return False


async def _load_wordlist() -> list[str]:
    path = Path(__file__).parent.parent / "data" / "wordlist.txt"
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text().splitlines()
            if l.strip() and not l.startswith("#")]


SENSITIVE = {
    ".env", ".git/config", ".git/HEAD", ".git/index", "backup.sql", "backup.zip",
    "dump.sql", "config.php.bak", "wp-config.php.bak", "id_rsa", ".aws/credentials",
    "actuator/env", "actuator/heapdump", "phpinfo.php", "info.php",
    ".env.bak", ".env.prod", ".env.production",
}


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    if not ctx.permissions.get("intrusive"):
        ctx.add(Finding(module=NAME,
                        title="Подбор путей пропущен (нет разрешения на активный скан)",
                        severity=Severity.INFO))
        return

    base = ctx.base_url
    baseline = await _baseline(client, base)
    ctx.baseline_404 = baseline

    words = await _load_wordlist()
    sem = asyncio.Semaphore(20)
    hits: list[tuple[str, int, int]] = []

    async def check(w: str):
        url = urljoin(base + "/", w.lstrip("/"))
        async with sem:
            try:
                r = await client.get(url)
            except Exception:
                return
        sig = page_signature(r.text)
        loc = r.headers.get("location", "")
        if r.status_code in (404,):
            return
        if _looks_like_baseline(r.status_code, sig, loc, baseline):
            return
        if r.status_code in (200, 201, 204, 301, 302, 401, 403, 500):
            hits.append((w, r.status_code, sig["len"]))
            sev = Severity.LOW
            human = ""
            fix = None
            if w in SENSITIVE and r.status_code in (200, 301, 302):
                sev = Severity.CRITICAL
                human = (" Это критично: файл содержит секреты или копию ваших данных."
                         if w.startswith(".env") or "backup" in w or "dump" in w or "config" in w
                         else " Это критично: открыт системный файл, не предназначенный для публичного доступа.")
                fix = ("Удалите файл с веб-сервера. Настройте веб-сервер блокировать доступ "
                       "к скрытым/служебным файлам (`.*`, `*.bak`, `*.sql`, `.git/`).")
            elif r.status_code in (401, 403):
                sev = Severity.INFO
                human = " (требует авторизации — это нормально)"
            elif r.status_code == 500:
                sev = Severity.MEDIUM
                human = " — сервер вернул ошибку. Это может указывать на необработанное исключение."
                fix = "Найдите причину 500 в логах. Не показывайте трассировку пользователям."

            ctx.add(Finding(
                module=NAME,
                title=f"Найден путь: /{w} (код {r.status_code})",
                severity=sev,
                url=url,
                description=f"Статус {r.status_code}, длина ответа {sig['len']} байт.{human}",
                cwe="CWE-538" if sev >= Severity.HIGH else None,
                remediation=fix,
            ))

    await asyncio.gather(*(check(w) for w in words))

    ctx.add(Finding(
        module=NAME,
        title=f"Подбор путей завершён: найдено {len(hits)} интересных",
        severity=Severity.INFO,
        raw={"hits": hits},
    ))
