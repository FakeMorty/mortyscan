"""Трёхступенчатый стресс-тест. ТОЛЬКО при явном разрешении.
Требует --i-own-this-target и подтверждённый allow_stress.

Важно: модуль оценивает устойчивость бережно и не пытается эскалировать нагрузку
до разрушительного уровня. Для «сильных» сайтов полезнее смотреть не только 5xx,
но и рост задержек (avg / p95 / p99 / max)."""
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


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    seq = sorted(values)
    idx = min(len(seq) - 1, max(0, int(round((pct / 100.0) * (len(seq) - 1)))))
    return seq[idx]


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
        p95 = _percentile(s["latencies"], 95)
        p99 = _percentile(s["latencies"], 99)
        mx = max(s["latencies"]) if s["latencies"] else 0
        msg = (f"волна {count} запросов / параллельно {conc}: "
               f"успешно={s['ok']}, провал={s['fail']}, 5xx={s['5xx']}, "
               f"429 (rate-limit)={s['rate_limited']}, средняя задержка={avg:.2f}с, "
               f"p95={p95:.2f}с, p99={p99:.2f}с, max={mx:.2f}с")
        sev = Severity.INFO
        if s["5xx"] > 0:
            sev = Severity.MEDIUM
        elif p95 >= 3 or p99 >= 4:
            sev = Severity.LOW
        if s["ok"] == 0:
            sev = Severity.LOW
        ctx.add(Finding(module=NAME, title=f"Результат волны: {count}×{conc}",
                        severity=sev, description=msg,
                        raw={**s, "avg": avg, "p95": p95, "p99": p99, "max": mx}))
        if s["rate_limited"] > 0:
            ctx.add(Finding(module=NAME,
                            title="Сработала защита от перегрузки (это хорошо)",
                            severity=Severity.INFO,
                            description=f"Сервер ответил 429 (Too Many Requests) {s['rate_limited']} раз. "
                                        "Значит у вас настроен rate-limit."))
        if s["5xx"] == 0 and s["ok"] > 0 and (p95 >= 3 or p99 >= 4):
            ctx.add(Finding(
                module=NAME,
                title="Под нагрузкой заметно растут задержки",
                severity=Severity.LOW,
                description=(
                    f"Сайт формально выдержал волну {count}×{conc}, но tail-latency выросла: "
                    f"p95={p95:.2f}с, p99={p99:.2f}с. Для крупных сайтов это полезный индикатор, "
                    "что система пока держится, но уже заметно проседает по времени ответа."
                ),
                remediation="Проверьте кэширование, пул соединений к БД, лимиты воркеров и настройки CDN/WAF."
            ))
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
