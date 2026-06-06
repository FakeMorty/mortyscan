"""Аудит HTTP-методов: OPTIONS, TRACE, WebDAV и потенциально опасные verb'ы.

Модуль остаётся проверочным: он не пытается загружать/удалять файлы,
а только смотрит, какие методы объявлены сервером и как тот отвечает на TRACE."""
from __future__ import annotations

import httpx

from ..core import Finding, ScanContext, Severity, rand_str

NAME = "methods"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False

_RISKY_METHODS = {"TRACE", "PUT", "DELETE", "PATCH", "MOVE", "COPY", "PROPFIND", "MKCOL"}


def _parse_allow(value: str) -> list[str]:
    return sorted({x.strip().upper() for x in (value or "").split(",") if x.strip()})


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    try:
        r = await client.options(ctx.base_url)
    except Exception:
        return

    allow = _parse_allow(r.headers.get("allow", ""))
    dav = r.headers.get("dav", "")
    if allow:
        ctx.add(Finding(
            module=NAME,
            title=f"HTTP-методы на корне сайта: {', '.join(allow)}",
            severity=Severity.INFO,
            description="Сервер объявил поддержку следующих HTTP-методов через ответ на OPTIONS.",
            evidence=f"Allow: {', '.join(allow)}",
            source="OPTIONS",
            confidence="high",
        ))

    risky = [m for m in allow if m in _RISKY_METHODS]
    if risky:
        sev = Severity.MEDIUM if "TRACE" in risky or dav else Severity.LOW
        ctx.add(Finding(
            module=NAME,
            title=f"Разрешены потенциально опасные HTTP-методы: {', '.join(risky)}",
            severity=sev,
            description=(
                "Сервер сообщает, что принимает нестандартные или потенциально опасные методы. "
                "Это не всегда уязвимость само по себе, но резко увеличивает площадь атаки: "
                "TRACE может участвовать в XST, PUT/WebDAV — открыть путь к записи файлов, "
                "MOVE/COPY/PROPFIND — раскрыть структуру хранилища."
            ),
            evidence=(f"Allow: {', '.join(allow)}" + (f"; DAV: {dav}" if dav else "")),
            remediation=(
                "Отключите всё, что приложению реально не нужно. Для обычного сайта обычно достаточно GET/HEAD/POST. "
                "TRACE почти всегда стоит отключить. Если WebDAV не используется — уберите его полностью."
            ),
            cwe="CWE-749",
            source="OPTIONS",
            confidence="medium",
        ))

    if dav:
        ctx.add(Finding(
            module=NAME,
            title="Похоже, включён WebDAV",
            severity=Severity.MEDIUM,
            description="Сервер вернул заголовок DAV. Если WebDAV не нужен по бизнес-логике, это лишняя поверхность атаки.",
            evidence=f"DAV: {dav}",
            remediation="Отключите WebDAV, если он не используется. Если используется — ограничьте доступ, включите аутентификацию и аудит.",
            cwe="CWE-16",
            source="OPTIONS",
            confidence="medium",
        ))

    if not (ctx.config.get("aggressive") and ctx.permissions.get("intrusive")):
        return

    canary = f"MortyTrace-{rand_str(8)}"
    try:
        tr = await client.request("TRACE", ctx.base_url, headers={"X-Morty-Trace": canary})
    except Exception:
        return

    body = tr.text or ""
    if tr.status_code < 400 and canary in body:
        ctx.add(Finding(
            module=NAME,
            title="TRACE отражает пользовательские заголовки (потенциальный XST)",
            severity=Severity.MEDIUM,
            description=(
                "TRACE-метод не просто включён, а ещё и возвращает обратно отправленные клиентом заголовки. "
                "Это классический паттерн для Cross-Site Tracing и признак лишней диагностической функциональности на проде."
            ),
            evidence=f"TRACE status={tr.status_code}; reflected header X-Morty-Trace: {canary}",
            remediation="Отключите TRACE на веб-сервере/прокси. Для диагностики используйте логи и специальные debug-endpoint'ы только во внутреннем контуре.",
            cwe="CWE-16",
            source="TRACE",
            confidence="high",
        ))
