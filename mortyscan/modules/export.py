"""SARIF, DefectDojo import-scan, and previous-report diff exports."""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx

from .. import __version__
from ..core import Finding, ScanContext, Severity

NAME = "export"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False
LOG = logging.getLogger("mortyscan.export")
_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "note", Severity.INFO: "note",
}
_SEVERITY_SCORE = {"CRITICAL": 90, "HIGH": 60, "MEDIUM": 30, "LOW": 10, "INFO": 0}


def _clean_url(value: str) -> str:
    try:
        parsed = urlparse(str(value))
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return urlunparse((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", "", ""))
    except Exception:
        pass
    return ""


def _evidence_hash(evidence: str) -> str:
    return hashlib.sha256(str(evidence or "").encode("utf-8", errors="replace")).hexdigest()


def _finding_identity(item: dict) -> tuple[str, str, str]:
    kind = str(item.get("type") or item.get("module") or "unknown")
    target = str(item.get("target") or "")
    return kind, target, _evidence_hash(str(item.get("evidence") or ""))


def _severity(item: dict) -> int:
    try:
        return int(item.get("severity_score"))
    except (TypeError, ValueError):
        label = str(item.get("severity", "INFO")).upper()
        return _SEVERITY_SCORE.get(label, 0)


def _load_report_findings(path: Path) -> tuple[list[dict], str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("previous report must be a JSON object")
    items = payload.get("находки", payload.get("findings", []))
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise ValueError("previous report has no findings array")
    return items, str(payload.get("цель") or payload.get("target") or "")


def build_diff(current: list[Finding], previous: list[dict]) -> dict:
    current_by_key = {_finding_identity(finding.to_dict()): finding.to_dict() for finding in current}
    previous_by_key = {_finding_identity(item): item for item in previous}
    current_keys, previous_keys = set(current_by_key), set(previous_by_key)

    def summary(item: dict) -> dict:
        return {"type": str(item.get("type") or item.get("module") or "unknown"),
                "target": str(item.get("target") or ""), "title": str(item.get("title") or "")[:240],
                "severity": str(item.get("severity") or "INFO"),
                "evidence_hash": _evidence_hash(str(item.get("evidence") or ""))}

    new = [summary(current_by_key[key]) for key in current_keys - previous_keys]
    fixed = [summary(previous_by_key[key]) for key in previous_keys - current_keys]
    still_open, regressed = [], []
    for key in current_keys & previous_keys:
        now, before = current_by_key[key], previous_by_key[key]
        item = summary(now)
        if _severity(now) > _severity(before):
            regressed.append(item)
        else:
            still_open.append(item)
    sort_key = lambda item: (item["type"], item["target"], item["evidence_hash"])
    return {"new": sorted(new, key=sort_key), "fixed": sorted(fixed, key=sort_key),
            "still_open": sorted(still_open, key=sort_key), "regressed": sorted(regressed, key=sort_key),
            "counts": {"new": len(new), "fixed": len(fixed), "still_open": len(still_open),
                       "regressed": len(regressed)}}


def build_sarif(ctx: ScanContext) -> dict:
    unique_rules: dict[str, dict] = {}
    results = []
    for finding in ctx.findings:
        rule_id = str(finding.type or finding.module or "unknown")[:120]
        unique_rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": rule_id.replace("_", " ")[:200]},
            "help": {"text": f"MortyScan finding type: {rule_id}"},
        })
        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(finding.severity, "note"),
            "message": {"text": (finding.title + (" — " + finding.description if finding.description else ""))[:4000]},
            "partialFingerprints": {"mortyscan/evidenceHash/v1": _evidence_hash(finding.evidence)},
            "properties": {"severity": finding.severity.label, "severityScore": int(finding.severity),
                           "findingId": finding.id, "target": finding.target,
                           "cwe": finding.cwe, "cvss": finding.cvss,
                           "confidence": finding.confidence, "source": finding.source,
                           "tags": finding.tags},
        }
        if finding.url:
            uri = _clean_url(finding.url)
            if uri:
                result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
        results.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "MortyScan", "version": __version__,
                                               "rules": [unique_rules[key] for key in sorted(unique_rules)]}},
                      "results": results}]}


def _dd_endpoint(value: str) -> str:
    parsed = urlparse(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ValueError("DefectDojo URL must be a clean HTTPS URL without userinfo/query/fragment")
    if parsed.path.rstrip("/").endswith("/api/v2/import-scan"):
        return value.rstrip("/") + "/"
    return value.rstrip("/") + "/api/v2/import-scan/"


def _defectdojo_sarif(ctx: ScanContext) -> bytes:
    return json.dumps(build_sarif(ctx), ensure_ascii=False, separators=(",", ":")).encode("utf-8")


async def _upload_defectdojo(ctx: ScanContext, sarif_bytes: bytes) -> bool:
    endpoint = _dd_endpoint(str(ctx.config.get("defectdojo_url") or ""))
    api_key = str(ctx.config.get("defectdojo_key") or "")
    engagement = int(ctx.config.get("defectdojo_engagement_id") or 0)
    if not api_key or engagement <= 0:
        raise ValueError("DefectDojo API key and positive engagement ID are required")
    parsed = urlparse(endpoint)
    LOG.warning("DefectDojo upload explicitly enabled: host=%s engagement=%s", parsed.hostname, engagement)
    transport = ctx.config.get("_defectdojo_test_transport")
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=False,
                                 proxy=ctx.config.get("proxy") or None, transport=transport) as client:
        response = await client.post(endpoint,
            headers={"Authorization": f"Token {api_key}"},
            data={"scan_type": "SARIF", "engagement": str(engagement), "active": "true",
                  "verified": "false", "close_old_findings": "false", "minimum_severity": "Info"},
            files={"file": ("mortyscan.sarif", sarif_bytes, "application/json")})
    return response.status_code in {200, 201, 202}


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    del client
    sarif_enabled = bool(ctx.config.get("sarif_enabled") or ctx.config.get("defectdojo_url"))
    diff_path = ctx.config.get("diff_from")
    dd_enabled = bool(ctx.config.get("defectdojo_url") or ctx.config.get("defectdojo_key"))
    if not (sarif_enabled or diff_path or dd_enabled):
        return
    if diff_path:
        try:
            previous, previous_target = _load_report_findings(Path(diff_path).expanduser())
            diff = build_diff(ctx.findings, previous)
            diff["previous_target"] = previous_target
            diff["current_target"] = ctx.target
            ctx.config["scan_diff"] = diff
            ctx.add(Finding(module=NAME, title="Diff отчётов: new/fixed/still_open/regressed",
                            severity=Severity.INFO,
                            description=("Новые: {new}; исправленные: {fixed}; остались: {still_open}; регрессии: {regressed}."
                                         .format(**diff["counts"])),
                            source="report diff", confidence="high", raw={"counts": diff["counts"]}))
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            ctx.add(Finding(module=NAME, title="Diff отчётов не выполнен",
                            severity=Severity.INFO, description=f"Предыдущий JSON не прочитан ({type(exc).__name__}).",
                            source="report diff", confidence="high"))
    sarif_bytes = b""
    if sarif_enabled:
        output = ctx.case_dir / "report.sarif"
        try:
            sarif_bytes = json.dumps(build_sarif(ctx), ensure_ascii=False, indent=2).encode("utf-8")
            output.write_bytes(sarif_bytes)
            ctx.config["sarif_path"] = str(output)
            ctx.add(Finding(module=NAME, title="SARIF 2.1.0 экспортирован",
                            severity=Severity.INFO, description="Создан локальный SARIF-отчёт.",
                            source="SARIF export", confidence="high", raw={"path": output.name}))
        except OSError as exc:
            ctx.add(Finding(module=NAME, title="SARIF экспорт не выполнен", severity=Severity.INFO,
                            description=f"Файл отчёта не записан ({type(exc).__name__}).", source="SARIF export"))
    if dd_enabled:
        if ctx.config.get("no_external"):
            ctx.add(Finding(module=NAME, title="DefectDojo upload пропущен (--no-external)", severity=Severity.INFO,
                            source="operator option", confidence="high"))
            ctx.config.pop("defectdojo_key", None)
        else:
            if not sarif_bytes:
                sarif_bytes = _defectdojo_sarif(ctx)
            try:
                uploaded = await _upload_defectdojo(ctx, sarif_bytes)
                ctx.add(Finding(module=NAME,
                    title="Отчёт отправлен в DefectDojo" if uploaded else "DefectDojo отклонил import-scan",
                    severity=Severity.INFO, description="Явно включённая передача SARIF на настроенный сервер DefectDojo; API key не журналировался.",
                    source="DefectDojo import-scan", confidence="high",
                    raw={"host": urlparse(str(ctx.config.get("defectdojo_url"))).hostname,
                         "engagement_id": int(ctx.config.get("defectdojo_engagement_id") or 0),
                         "http_success": uploaded}))
            except Exception as exc:
                LOG.warning("DefectDojo upload failed (%s)", type(exc).__name__)
                ctx.add(Finding(module=NAME, title="DefectDojo upload не выполнен", severity=Severity.INFO,
                                description=f"Import-scan не завершён ({type(exc).__name__}); API key и тело ответа не записаны.",
                                source="DefectDojo import-scan", confidence="high"))
            finally:
                ctx.config.pop("defectdojo_key", None)
