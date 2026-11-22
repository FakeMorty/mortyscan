"""Проверка обнаруженных форм на очевидные маркеры CSRF-защиты (без отправки формы)."""
from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "csrf_audit"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False

_TOKEN_NAME = re.compile(
    r"(?:csrf|xsrf|authenticity[_-]?token|requestverificationtoken|antiforgery|_token)",
    re.IGNORECASE,
)
_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def _in_scope(url: str, ctx: ScanContext) -> bool:
    try:
        parsed = urlparse(url)
        base = urlparse(ctx.base_url)
        return parsed.scheme in {"http", "https"} and parsed.hostname == base.hostname
    except Exception:
        return False


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    del client  # Модуль работает только с инвентарём краулера и не отправляет запросов.
    forms = [form for form in ctx.discovered_forms if _in_scope(form.get("url", ""), ctx)]
    for form in forms:
        method = str(form.get("method", "GET")).upper()
        if method not in _STATE_CHANGING:
            continue
        fields = form.get("inputs", [])
        token_fields = [
            str(field.get("name", "")) for field in fields
            if _TOKEN_NAME.search(str(field.get("name", "")))
        ]
        if token_fields:
            continue
        ctx.add(Finding(
            module=NAME,
            title=f"В форме {method} не найдено очевидного CSRF-токена",
            severity=Severity.LOW,
            cwe="CWE-352",
            url=form.get("url"),
            evidence=f"method={method}; поля={', '.join(str(f.get('name', '')) for f in fields)[:240] or '(нет)' }",
            description="Краулер обнаружил форму, меняющую состояние, но не увидел в её полях "
                        "распространённых имён CSRF-токена. Это повод проверить защиту вручную, "
                        "но не доказательство уязвимости: токен может передаваться нестандартно "
                        "или защита может опираться на другие механизмы.",
            remediation="Для cookie-аутентифицированных операций применяйте synchronizer token "
                        "или double-submit token, проверяйте Origin/Referer и используйте подходящий "
                        "SameSite для сессионных cookie. Не полагайтесь только на скрытое поле без серверной проверки.",
            confidence="low",
        ))

    ctx.add(Finding(
        module=NAME,
        title=f"Анализ CSRF-форм завершён: форм {len(forms)}",
        severity=Severity.INFO,
        description="Проверены только формы из инвентаря краулера; формы не отправлялись и данные не изменялись.",
        raw={"forms_checked": len(forms)},
    ))
