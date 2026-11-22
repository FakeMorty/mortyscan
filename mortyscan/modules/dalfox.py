"""Optional Dalfox adapter for XSS candidates from vulns and aggressive param mining."""
from __future__ import annotations

import json
import logging
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

import httpx

from ..core import Finding, ScanContext, Severity, host_in_scope, same_origin
from ..tools.runner import ToolNotFound, run_tool
from .crawler import _registrable

NAME = "dalfox"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False
LOG = logging.getLogger("mortyscan.dalfox")


def _candidate_urls(ctx: ScanContext) -> list[tuple[str, str]]:
    candidates: dict[str, str] = {}
    for item in ctx.xss_candidates:
        url = str(item.get("url", ""))
        if url:
            candidates[url] = str(item.get("param", ""))
    if ctx.config.get("aggressive"):
        for path, names in (ctx.discovered_params or {}).items():
            url = httpx.URL(ctx.base_url).join(path)
            query = dict(parse_qsl(url.query.decode("utf-8", errors="replace"), keep_blank_values=True))
            for name in names:
                query.setdefault(str(name), "1")
            if query:
                url = url.copy_with(query=urlencode(query).encode())
                candidates[str(url)] = ",".join(sorted(str(name) for name in names))
    scope = set(ctx.config.get("scope_hosts", []))
    result = []
    for url, param in candidates.items():
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        if scope:
            in_scope = host_in_scope(parsed.hostname, scope)
        else:
            in_scope = _registrable(parsed.hostname) == _registrable(ctx.target)
        if not in_scope:
            continue
        result.append((url, param))
    return sorted(result)


def _parse_records(text: str) -> list[dict]:
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data.get("data", [data]) if isinstance(data.get("data", [data]), list) else [data]
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
    except json.JSONDecodeError:
        pass
    records = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _record_finding(ctx: ScanContext, fallback_url: str, record: dict) -> None:
    kind = str(record.get("type") or record.get("poc_type") or record.get("vuln_type") or "reflected").lower()
    severity = Severity.CRITICAL if "stored" in kind else Severity.HIGH if "dom" in kind else Severity.MEDIUM
    url = str(record.get("data") or record.get("url") or fallback_url)
    param = str(record.get("param") or record.get("parameter") or "")[:100]
    evidence_parts = [f"type={kind[:80]}"]
    if param:
        evidence_parts.append(f"parameter={param}")
    if record.get("message"):
        evidence_parts.append("message=" + str(record["message"])[:200])
    ctx.add(Finding(
        module=NAME,
        title=f"Dalfox обнаружил XSS ({kind[:80]})",
        severity=severity, cwe="CWE-79", url=url,
        evidence="; ".join(evidence_parts),
        description="Результат Dalfox для URL, выбранного по reflection из vulns или по параметрам краулера.",
        remediation="Экранируйте вывод с учётом HTML/DOM-контекста и используйте безопасные DOM API.",
        source="Dalfox JSON", confidence="high" if "dom" in kind or "stored" in kind else "medium",
        tags=["xss", "dalfox", kind[:40]],
        raw={"type": kind[:80], "parameter": param or None},
    ))


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    del client
    if not ctx.config.get("dalfox_enabled"):
        return
    if not ctx.permissions.get("intrusive"):
        ctx.add(Finding(module=NAME, title="Dalfox пропущен: нет активного разрешения",
                        severity=Severity.INFO, source="permission gate", confidence="high"))
        return
    if ctx.config.get("no_external"):
        ctx.add(Finding(module=NAME, title="Dalfox пропущен по --no-external", severity=Severity.INFO,
                        source="operator option", confidence="high"))
        return
    if ctx.waf and not ctx.config.get("aggressive"):
        ctx.add(Finding(module=NAME, title="Dalfox пропущен: обнаружен WAF",
                        severity=Severity.INFO,
                        description="Без --aggressive Dalfox не запускается при наличии fingerprint WAF.",
                        source="WAF safety gate", confidence="high"))
        return
    urls = _candidate_urls(ctx)
    if not urls:
        ctx.add(Finding(module=NAME, title="Dalfox пропущен: XSS-кандидатов нет",
                        severity=Severity.INFO,
                        description="Запуск разрешён только для отражений из vulns; --aggressive также использует параметры краулера.",
                        source="candidate gate", confidence="high"))
        return
    timeout = max(1, min(180, int(ctx.config.get("dalfox_timeout", 120))))
    LOG.warning("Dalfox explicitly enabled for target=%s candidate_urls=%s oast=%s",
                ctx.target, min(len(urls), 100), bool(ctx.config.get("oast")))
    ran = skipped = 0
    for url, _param in urls[:100]:
        args = ["dalfox", "url", url, "--silence", "--output", "json", "--no-spinner",
                "--mining-dom", "--mining-dict", "--deep-domxss", "--worker", "10", "--timeout", "10"]
        if same_origin(url, ctx.base_url):
            if ctx.config.get("cookie"):
                args.extend(["-H", "Cookie: " + str(ctx.config["cookie"])])
            for header in ctx.config.get("request_headers", []):
                args.extend(["-H", str(header)])
        if ctx.config.get("proxy"):
            args.extend(["--proxy", str(ctx.config["proxy"])])
        if ctx.config.get("oast") and ctx.config.get("interactsh_url"):
            args.extend(["--blind", str(ctx.config["interactsh_url"])])
            ctx.add(Finding(module=NAME, title="Dalfox OAST явно включён",
                            severity=Severity.INFO, url=url,
                            description="Внешние OAST callbacks могут быть отправлены для этой цели.",
                            source="operator opt-in", confidence="high", tags=["oast", "external-effect"]))
        try:
            result = await run_tool(args, timeout=timeout)
        except ToolNotFound:
            ctx.add(Finding(module=NAME, title="Dalfox не установлен — проверка пропущена",
                            severity=Severity.INFO, description="Установите Dalfox и повторите явный запуск с --dalfox.",
                            source="tool availability", confidence="high"))
            return
        except TimeoutError:
            skipped += 1
            ctx.add(Finding(module=NAME, title="Dalfox остановлен по таймауту", severity=Severity.INFO,
                            url=url, description=f"Превышен лимит {timeout} секунд.",
                            source="subprocess timeout", confidence="high"))
            continue
        ran += 1
        for record in _parse_records(result.stdout):
            _record_finding(ctx, url, record)
    ctx.add(Finding(module=NAME, title=f"Dalfox завершён: URL обработано {ran}, остановлено {skipped}",
                    severity=Severity.INFO,
                    raw={"urls_run": ran, "urls_skipped": skipped, "oast_enabled": bool(ctx.config.get("oast"))}))
