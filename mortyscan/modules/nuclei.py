"""Явно opt-in запуск Nuclei по безопасным шаблонам без OAST/default-logins."""
from __future__ import annotations

import logging
import re
import tempfile
from pathlib import Path
from typing import Any

import httpx

from ..core import Finding, ScanContext, Severity
from ..tools.runner import ToolNotFound, run_tool

NAME = "nuclei"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False
LOG = logging.getLogger("mortyscan.nuclei")

_SEVERITIES = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}
_SECRET_RE = re.compile(r"(?i)(authorization\s*:\s*(?:bearer\s+)?|cookie\s*:\s*)[^\r\n\"']+")


def _normalize_json(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def _redact(value: Any) -> str:
    text = str(value or "")
    return _SECRET_RE.sub(r"\1<redacted>", text)[:2000]


def _finding(ctx: ScanContext, record: dict[str, Any]) -> Finding | None:
    info = record.get("info") or {}
    if not isinstance(info, dict):
        info = {}
    template_id = str(record.get("template-id") or record.get("templateID") or "nuclei-unknown")
    matched = str(record.get("matched-at") or record.get("matched") or ctx.base_url)
    severity = _SEVERITIES.get(str(info.get("severity", "info")).lower(), Severity.INFO)
    name = str(info.get("name") or template_id)
    details = []
    if record.get("matcher-name"):
        details.append(f"matcher={record['matcher-name']}")
    if record.get("extracted-results"):
        details.append("extracted=" + _redact(record["extracted-results"]))
    if record.get("curl-command"):
        details.append("curl=" + _redact(record["curl-command"]))
    description = str(info.get("description") or "Обнаружено шаблоном Nuclei.")
    refs = info.get("reference") or info.get("reference-url") or []
    if isinstance(refs, str):
        refs = [refs]
    elif not isinstance(refs, (list, tuple)):
        refs = []
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
    elif not isinstance(tags, (list, tuple, set)):
        tags = []
    return Finding(
        module=NAME, type=template_id,
        title=f"Nuclei: {name}", severity=severity,
        description=description[:3000], url=matched,
        target=ctx.target, evidence="; ".join(details)[:3000],
        remediation=str(info.get("remediation") or "Проверьте находку вручную и исправьте первопричину."),
        references=[str(ref) for ref in refs[:10]],
        source="Nuclei template", confidence="high",
        tags=[str(tag) for tag in tags if str(tag)][:30],
        raw={"template_id": template_id, "matched_at": matched,
             "matcher_name": record.get("matcher-name")},
    )


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    del client  # Nuclei is a separate, explicitly opted-in process.
    if not ctx.config.get("nuclei_enabled"):
        return
    if ctx.config.get("no_external"):
        ctx.add(Finding(module=NAME, title="Nuclei пропущен (--no-external)", severity=Severity.INFO))
        return
    if ctx.config.get("scope_hosts"):
        ctx.add(Finding(
            module=NAME, title="Nuclei пропущен при активном --scope-file", severity=Severity.INFO,
            description="Внешний бинарник не подключён к HTTPX scope-guard; для гарантии ограничения области запуска пропущен.",
            source="scope enforcement", confidence="high",
        ))
        return
    target = ctx.base_url
    with tempfile.TemporaryDirectory(prefix="mortyscan-nuclei-") as directory:
        target_file = Path(directory) / "targets.txt"
        target_file.write_text(target + "\n", encoding="utf-8")
        cmd = [
            "nuclei", "-l", str(target_file), "-jsonl", "-silent",
            "-severity", "medium,high,critical",
            "-t", "http/cves/", "-t", "http/exposures/", "-t", "http/misconfiguration/", "-t", "http/takeovers/",
            "-rate-limit", str(max(1, min(50, int(ctx.config.get("rate_limit", 10))))),
            "-timeout", "10", "-retries", "1", "-no-interactsh", "-disable-redirects",
        ]
        tags = str(ctx.config.get("nuclei_tags", "")).strip()
        exclude_tags = str(ctx.config.get("nuclei_exclude_tags", "")).strip()
        templates = str(ctx.config.get("nuclei_templates", "")).strip()
        required_excludes = {"dos", "intrusive", "bruteforce", "default-login", "oast", "headless", "fuzz"}
        required_excludes.update(tag.strip() for tag in exclude_tags.split(",") if tag.strip())
        if tags:
            cmd.extend(["-tags", tags])
        cmd.extend(["-exclude-tags", ",".join(sorted(required_excludes))])
        if templates:
            cmd.extend(["-t", templates])
        tool_headers = list(ctx.config.get("request_headers", []))
        if ctx.config.get("cookie"):
            tool_headers.append("Cookie: " + str(ctx.config["cookie"]))
        for header in tool_headers:
            cmd.extend(["-H", str(header)])
        if ctx.config.get("proxy"):
            cmd.extend(["-proxy", str(ctx.config["proxy"])])
        timeout = max(1, min(1800, int(ctx.config.get("nuclei_timeout", 600))))
        LOG.warning("Nuclei explicitly enabled for target=%s; selected templates may send active HTTP probes", ctx.target)
        try:
            result = await run_tool(cmd, timeout=timeout, capture_json=True)
        except ToolNotFound:
            ctx.add(Finding(
                module=NAME, title="Внешний инструмент не установлен: nuclei",
                severity=Severity.INFO,
                description="Установите Nuclei отдельно или отключите запуск флагом --no-external.",
                raw={"tool_missing": "nuclei"}, source="tool availability", confidence="high",
            ))
            LOG.warning("tool_missing: nuclei")
            return
        except TimeoutError as exc:
            ctx.add(Finding(
                module=NAME, title="Nuclei остановлен по таймауту", severity=Severity.INFO,
                description=str(exc), source="subprocess timeout", confidence="high",
            ))
            return
        if result.stderr:
            LOG.warning("nuclei stderr: %s", _redact(result.stderr)[:1000])
        records = _normalize_json(result.json_data)
        dedup: set[tuple[str, str]] = set()
        for record in records:
            item = _finding(ctx, record)
            if item is None:
                continue
            key = (str(item.type), str(item.url))
            if key in dedup:
                continue
            dedup.add(key)
            ctx.add(item)
        if result.returncode and not records:
            ctx.add(Finding(
                module=NAME, title=f"Nuclei завершился с кодом {result.returncode}", severity=Severity.INFO,
                description=_redact(result.stderr)[:1000] or "Nuclei не вернул JSONL-результаты.",
                source="external tool", confidence="high",
            ))
        elif result.stdout_truncated:
            ctx.add(Finding(
                module=NAME, title="Вывод Nuclei усечён лимитом безопасности", severity=Severity.LOW,
                description="Часть stdout превышала внутренний лимит захвата; некоторые результаты могли быть потеряны.",
                source="output capture", confidence="high",
            ))
