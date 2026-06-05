"""Аудит HTTP-заголовков и cookie."""
from __future__ import annotations

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "headers"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False

# (заголовок, серьёзность_если_отсутствует, как_исправить)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", Severity.MEDIUM,
     "Добавьте: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload. "
     "Это заставит браузер всегда ходить к вам по HTTPS."),
    ("Content-Security-Policy", Severity.MEDIUM,
     "Опишите CSP — список «откуда можно загружать скрипты, картинки и т.д.». "
     "Это самая мощная защита от XSS."),
    ("X-Frame-Options", Severity.LOW,
     "Добавьте: X-Frame-Options: DENY (или используйте CSP frame-ancestors). "
     "Защищает от clickjacking — когда ваш сайт «оборачивают» в невидимый фрейм."),
    ("X-Content-Type-Options", Severity.LOW,
     "Добавьте: X-Content-Type-Options: nosniff. "
     "Запрещает браузеру «угадывать» тип файла."),
    ("Referrer-Policy", Severity.LOW,
     "Добавьте: Referrer-Policy: strict-origin-when-cross-origin. "
     "Ограничивает, какая информация уходит на сторонние сайты при переходе."),
    ("Permissions-Policy", Severity.INFO,
     "Опишите Permissions-Policy, чтобы запретить доступ к камере, микрофону, "
     "геолокации тем модулям сайта, которым это не нужно."),
]

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                 "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache"]


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    try:
        r = await client.get(ctx.base_url)
    except Exception as e:
        ctx.add(Finding(module=NAME, title="Сайт недоступен",
                        description=f"Не удалось получить ответ: {e}",
                        severity=Severity.HIGH))
        return

    ctx.headers = dict(r.headers)

    # Отсутствующие защитные заголовки
    for h, sev, fix in SECURITY_HEADERS:
        if h.lower() not in {k.lower() for k in r.headers}:
            ctx.add(Finding(
                module=NAME,
                title=f"Отсутствует заголовок безопасности: {h}",
                severity=sev,
                description=f"Сервер не отдаёт заголовок {h}. "
                            "Браузер не получает важную защитную инструкцию.",
                remediation=fix,
                cwe="CWE-693",
                url=ctx.base_url,
            ))

    # Утечка информации о технологиях
    for h in LEAKY_HEADERS:
        if h in r.headers:
            val = r.headers[h]
            ctx.tech[h] = val
            ctx.add(Finding(
                module=NAME,
                title=f"Утечка технологии через заголовок {h}",
                severity=Severity.LOW,
                description=f"Сервер сообщает в открытую: {h}: {val}. "
                            "Это упрощает злоумышленнику поиск готовых эксплойтов под вашу версию.",
                remediation=f"Скройте или обобщите заголовок {h} в настройках веб-сервера "
                            "(`server_tokens off` для nginx, `ServerTokens Prod` для apache).",
                cwe="CWE-200",
                url=ctx.base_url,
            ))

    # Cookies
    cookies_raw = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else \
                  r.headers.get("set-cookie", "").split(",")
    for sc in cookies_raw:
        if not sc:
            continue
        low = sc.lower()
        issues = []
        if "httponly" not in low: issues.append("нет HttpOnly")
        if "secure"   not in low: issues.append("нет Secure")
        if "samesite" not in low: issues.append("нет SameSite")
        if issues:
            ctx.add(Finding(
                module=NAME,
                title="Небезопасные cookie",
                severity=Severity.MEDIUM,
                description=f"Cookie «{sc.split('=')[0][:40]}»: {', '.join(issues)}. "
                            "Если в коде есть XSS — без HttpOnly злоумышленник угоняет сессию из JavaScript. "
                            "Без Secure cookie уходит по нешифрованному HTTP. Без SameSite возможна CSRF-атака.",
                remediation="Для всех сессионных cookie выставьте флаги: "
                            "HttpOnly, Secure, SameSite=Lax (или Strict).",
                cwe="CWE-1004",
                url=ctx.base_url,
                evidence=sc[:200],
            ))

    # Быстрая проверка CORS
    try:
        cors = await client.get(
            ctx.base_url,
            headers={"Origin": "https://evil.example.com"},
        )
        acao = cors.headers.get("access-control-allow-origin", "")
        acac = cors.headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            ctx.add(Finding(
                module=NAME,
                title="Опасная настройка CORS: ACAO=* + credentials=true",
                severity=Severity.HIGH, cwe="CWE-942",
                description="Сервер разрешает читать ответы с любого источника И передавать cookie. "
                            "Это запрещено стандартом и крайне опасно: любой сторонний сайт может "
                            "от имени вашего залогиненного пользователя читать его данные.",
                remediation="Возвращайте Access-Control-Allow-Origin только для конкретных доверенных доменов "
                            "из белого списка. Никогда не комбинируйте «*» и credentials.",
                url=ctx.base_url, evidence=f"ACAO={acao}, ACAC={acac}",
            ))
        elif acao == "https://evil.example.com":
            ctx.add(Finding(
                module=NAME,
                title="CORS отражает любой Origin",
                severity=Severity.HIGH, cwe="CWE-942",
                description="Сервер бездумно возвращает в ACAO любой Origin, который ему прислали. "
                            "Это позволяет любому сайту читать ответы от вашего сервера через жертву.",
                remediation="Проверяйте Origin по строгому белому списку.",
                url=ctx.base_url, evidence=f"ACAO={acao}",
            ))
    except Exception:
        pass
