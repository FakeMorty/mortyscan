"""Optional SQLMap confirmation for SQLi candidates already identified by vulns."""
from __future__ import annotations

import logging
import re
import shlex
from urllib.parse import urlencode, urlparse

import httpx

from ..core import Finding, ScanContext, Severity, host_in_scope, same_origin
from ..tools.runner import ToolNotFound, run_tool
from .crawler import _registrable
from .waf import get_tamper_chain

NAME = "sqlmap"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False
LOG = logging.getLogger("mortyscan.sqlmap")

_BLACKLIST_DEFAULT = {"logout", "delete", "remove", "unsubscribe"}
_PARAM_RE = re.compile(r"(?im)^\s*Parameter:\s*(.+?)\s*$")
_DBMS_RE = re.compile(r"(?im)^\s*back-end DBMS:\s*(.+?)\s*$")
_DETAILS_RE = re.compile(r"(?im)^\s*(Type|Title|Payload):\s*(.+?)\s*$")

_DANGEROUS_EXTRA = (
    "-u", "--url", "--data", "--method", "-p", "--param", "--output-dir", "--crawl", "--forms",
    "--dump", "--dump-all", "--dump-format", "--file-read", "--file-write",
    "--os-shell", "--os-pwn", "--os-cmd", "--sql-shell", "--sql-file",
    "--udf-inject", "--priv-esc", "--passwords", "--reg-read", "--reg-add",
    "--reg-del", "--all", "--wizard", "--eval", "--proxy-file", "--tor",
)


def _blocked(url: str, ctx: ScanContext) -> bool:
    parsed = urlparse(url)
    path_parts = {part.lower() for part in parsed.path.split("/") if part}
    blacklist = {str(x).strip().lower() for x in ctx.config.get("sqlmap_blacklist", _BLACKLIST_DEFAULT)}
    return any(marker in part for part in path_parts for marker in blacklist)


def _waf_tamper(ctx: ScanContext) -> str:
    names = [str(item.get("name", "")) for item in ctx.waf if isinstance(item, dict)]
    if not names:
        return ""
    return ",".join(get_tamper_chain(names[0]))


def _extra_args(ctx: ScanContext) -> list[str]:
    raw = str(ctx.config.get("sqlmap_extra", "") or "")
    if not raw.strip():
        return []
    try:
        args = shlex.split(raw)
    except ValueError as exc:
        raise ValueError("Некорректные кавычки в --sqlmap-extra") from exc
    lowered = [arg.lower().split("=", 1)[0] for arg in args]
    forbidden = [arg for arg in lowered if any(
        arg == option or arg.startswith(option + "=") or arg.startswith(option + "-")
        or (option == "-u" and arg.startswith("-u") and not arg.startswith("--"))
        for option in _DANGEROUS_EXTRA)]
    if forbidden:
        raise ValueError("Опасные SQLMap-флаги запрещены в --sqlmap-extra: " + ", ".join(forbidden))
    return args


def _data_string(item: dict) -> str:
    values = item.get("base_params") or {}
    return urlencode([(str(key), str(value)) for key, value in values.items()])


def _findings_from_output(ctx: ScanContext, url: str, param: str, output: str) -> int:
    parameters = _PARAM_RE.findall(output)
    details = _DETAILS_RE.findall(output)
    dbms = _DBMS_RE.findall(output)
    if not parameters and ("injectable" in output.lower() or "is vulnerable" in output.lower()):
        parameters = [param]
    unique = list(dict.fromkeys(value.strip() for value in parameters if value.strip()))
    for found_param in unique:
        ctx.add(Finding(
            module=NAME,
            title=f"SQLMap подтвердил SQL-инъекцию в параметре «{found_param[:100]}»",
            severity=Severity.CRITICAL, cwe="CWE-89", cvss=9.8, url=url,
            evidence="; ".join([f"parameter={found_param[:100]}",
                                *(f"{kind}={value[:240]}" for kind, value in details[:8]),
                                *(f"back-end DBMS={value[:120]}" for value in dbms[:1])]),
            description="SQLMap подтвердил инъекцию для параметра, уже отмеченного модулем vulns. Дамп данных не выполнялся, если он не был отдельно разрешён.",
            remediation="Используйте параметризованные запросы и минимальные привилегии БД. Проверьте логи доступа и устраните причину.",
            source="SQLMap", confidence="high", tags=["sqli", "sqlmap", "confirmed"],
            raw={"parameter": found_param[:100], "dbms": dbms[:1],
                 "details": [{"type": kind, "value": value[:240]} for kind, value in details[:8]]},
        ))
    return len(unique)


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    del client
    if not ctx.config.get("sqlmap_enabled"):
        return
    if not ctx.permissions.get("intrusive"):
        ctx.add(Finding(module=NAME, title="SQLMap пропущен: нет активного разрешения",
                        severity=Severity.INFO, source="permission gate", confidence="high"))
        return
    if ctx.config.get("no_external"):
        ctx.add(Finding(module=NAME, title="SQLMap пропущен по --no-external", severity=Severity.INFO,
                        source="operator option", confidence="high"))
        return
    candidates = ctx.sqli_candidates
    if not candidates:
        ctx.add(Finding(module=NAME, title="SQLMap пропущен: SQLi-кандидатов нет",
                        severity=Severity.INFO, description="Модуль запускается только для URL, отмеченных vulns.",
                        source="sqli candidate gate", confidence="high"))
        return
    if ctx.config.get("dump_data") and not ctx.config.get("dump_data_confirmed"):
        ctx.add(Finding(module=NAME, title="SQLMap --dump заблокирован: нет подтверждения",
                        severity=Severity.INFO, source="safety gate", confidence="high"))
        return

    output_root = ctx.case_dir / "sqlmap"
    output_root.mkdir(parents=True, exist_ok=True)
    timeout = max(1, min(180, int(ctx.config.get("sqlmap_timeout", 180))))
    extra = _extra_args(ctx)
    tamper = _waf_tamper(ctx)
    LOG.warning("SQLMap explicitly enabled for target=%s candidate_urls=%s dump=%s",
                ctx.target, min(len(candidates), 100), bool(ctx.config.get("dump_data")))
    if ctx.config.get("dump_data"):
        LOG.warning("SQLMap --dump-data confirmed interactively for target=%s; database contents may be exposed", ctx.target)
    ran = 0
    skipped = 0

    for item in candidates:
        url = str(item.get("url", ""))
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            skipped += 1
            continue
        scope_hosts = set(ctx.config.get("scope_hosts", []))
        if scope_hosts:
            in_scope = host_in_scope(parsed.hostname, scope_hosts)
        else:
            in_scope = _registrable(parsed.hostname) == _registrable(ctx.target)
        if not in_scope:
            skipped += 1
            continue
        if _blocked(url, ctx):
            skipped += 1
            ctx.add(Finding(module=NAME, title="SQLMap пропущен: destructive-like URL",
                            severity=Severity.INFO, url=url,
                            description="Путь содержит logout/delete/remove/unsubscribe (или дополнительный blacklist).",
                            source="safety blacklist", confidence="high"))
            continue
        param = str(item.get("param", ""))
        if not param:
            skipped += 1
            continue
        dbms_hint = str(item.get("dbms_hint", ""))
        safe_dbms = dbms_hint if re.fullmatch(r"[A-Za-z0-9 _.-]{1,40}", dbms_hint) else ""
        args = ["sqlmap", "-u", url, "-p", param, "--batch", "--smart",
                "--level=2", "--risk=2", "--threads=2", "--timeout=10",
                "--ignore-redirects", "--output-dir", str(output_root)]
        if str(item.get("method", "GET")).upper() == "POST":
            args.extend(["--method=POST", "--data", _data_string(item)])
        if safe_dbms:
            args.extend(["--dbms", safe_dbms])
        if ctx.config.get("aggressive"):
            args.extend(["--level=4", "--risk=3", "--technique=BEUSTQ"])
        if tamper:
            args.append(f"--tamper={tamper}")
        if same_origin(url, ctx.base_url):
            if ctx.config.get("cookie"):
                args.extend(["--cookie", str(ctx.config["cookie"])])
            headers = [str(value) for value in ctx.config.get("request_headers", []) if ":" in str(value)]
            if headers:
                args.extend(["--headers", "\\n".join(headers)])
        if ctx.config.get("proxy"):
            args.extend(["--proxy", str(ctx.config["proxy"])])
        args.extend(extra)
        if ctx.config.get("dump_data"):
            args.append("--dump")
        try:
            result = await run_tool(args, timeout=timeout)
        except ToolNotFound:
            ctx.add(Finding(module=NAME, title="SQLMap не установлен — проверка пропущена",
                            severity=Severity.INFO, description="Установите sqlmap и повторите явный запуск с --sqlmap.",
                            source="tool availability", confidence="high"))
            return
        except TimeoutError:
            ctx.add(Finding(module=NAME, title="SQLMap остановлен по таймауту",
                            severity=Severity.INFO, url=url,
                            description=f"Превышен лимит {timeout} секунд для одного URL; процесс завершён.",
                            source="subprocess timeout", confidence="high"))
            continue
        ran += 1
        output = result.stdout + "\n" + result.stderr
        found = _findings_from_output(ctx, url, param, output)
        if not found:
            LOG.info("sqlmap completed without a parsed injectable parameter for %s (rc=%s)", url, result.returncode)

    ctx.add(Finding(module=NAME, title=f"SQLMap завершён: URL обработано {ran}, пропущено {skipped}",
                    severity=Severity.INFO,
                    description="SQLMap запускался только на SQLi-подозрительных URL; штатный и aggressive режимы не выгружают данные.",
                    raw={"urls_run": ran, "urls_skipped": skipped, "dump_enabled": bool(ctx.config.get("dump_data")),
                         "timeout_seconds": timeout, "waf_tamper": tamper or None}))
