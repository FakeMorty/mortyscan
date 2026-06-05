"""Трёхступенчатый стресс-тест. ТОЛЬКО при явном разрешении.
Требует --i-own-this-target и подтверждённый allow_stress."""
from __future__ import annotations

import asyncio
import time

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "stress"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = True


async def _wave(client, url, count, concurrency):
    sem = asyncio.Semaphore(concurrency)
    stats = {"ok": 0, "fail": 0, "5xx": 0, "rate_limited": 0, "latencies": []}

    async def one():
        async with sem:
            t0 = time.monotonic()
            try:
                r = await client.get(url, timeout=5)
                dt = time.monotonic() - t0
                stats["latencies"].append(dt)
                if r.status_code == 429:
                    stats["rate_limited"] += 1
                elif 500 <= r.status_code < 600:
                    stats["5xx"] += 1
                    stats["fail"] += 1
                elif 200 <= r.status_code < 400:
                    stats["ok"] += 1
                else:
                    stats["fail"] += 1
            except Exception:
                stats["fail"] += 1

    await asyncio.gather(*(one() for _ in range(count)))
    return stats


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    if not ctx.permissions.get("stress"):
        ctx.add(Finding(module=NAME, title="Стресс-тест пропущен (нет разрешения)",
                        severity=Severity.INFO,
                        description="Для запуска: --stress + --i-own-this-target."))
        return

    url = ctx.base_url
    stages = ctx.config.get("stress_stages", [(30, 10), (100, 25), (300, 50)])
    for count, conc in stages:
        s = await _wave(client, url, count, conc)
        avg = sum(s["latencies"]) / len(s["latencies"]) if s["latencies"] else 0
        msg = (f"волна {count} запросов / параллельно {conc}: "
               f"успешно={s['ok']}, провал={s['fail']}, 5xx={s['5xx']}, "
               f"429 (rate-limit)={s['rate_limited']}, средняя задержка={avg:.2f}с")
        sev = Severity.INFO
        if s["5xx"] > 0:
            sev = Severity.MEDIUM
        if s["ok"] == 0:
            sev = Severity.LOW
        ctx.add(Finding(module=NAME, title=f"Результат волны: {count}×{conc}",
                        severity=sev, description=msg, raw=s))
        if s["rate_limited"] > 0:
            ctx.add(Finding(module=NAME,
                            title="Сработала защита от перегрузки (это хорошо)",
                            severity=Severity.INFO,
                            description=f"Сервер ответил 429 (Too Many Requests) {s['rate_limited']} раз. "
                                        "Значит у вас настроен rate-limit."))
        if s["ok"] == 0 and s["fail"] > 0:
            ctx.add(Finding(module=NAME,
                            title=f"Сервер перестал отвечать на этапе {count}",
                            severity=Severity.MEDIUM,
                            description="Все запросы провалились. Либо нас заблокировали "
                                        "(это хорошо), либо сервер не справился (это плохо).",
                            remediation="Если сервер упал — добавить мощностей и rate-limiting. "
                                        "Если нас заблокировали — отлично."))
            break
        await asyncio.sleep(1.0)
