"""Correlate independent findings into declarative attack paths (no network activity)."""
from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "chain"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False
LOG = logging.getLogger("mortyscan.chain")
MAX_RULES = 100
MAX_CONDITIONS = 10
_VALID_SEVERITIES = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                     "medium": Severity.MEDIUM, "low": Severity.LOW}


def _rules_path(ctx: ScanContext) -> Path:
    configured = ctx.config.get("chain_rules_path")
    return Path(configured) if configured else Path(__file__).resolve().parents[1] / "data" / "chains.yaml"


def _contains_any(value: object, terms: object) -> bool:
    if not isinstance(terms, list) or not terms:
        return False
    text = str(value or "").lower()
    return any(str(term).lower() in text for term in terms if str(term))


def _matches(finding: Finding, condition: dict) -> bool:
    if condition.get("module") and finding.module.lower() != str(condition["module"]).lower():
        return False
    if condition.get("type") and str(finding.type or "").lower() != str(condition["type"]).lower():
        return False
    if condition.get("tag_any"):
        tags = {str(tag).lower() for tag in finding.tags}
        if not tags.intersection(str(tag).lower() for tag in condition["tag_any"]):
            return False
    if condition.get("title_contains_any") and not _contains_any(finding.title, condition["title_contains_any"]):
        return False
    if condition.get("title_requires_any") and not _contains_any(finding.title, condition["title_requires_any"]):
        return False
    if condition.get("evidence_contains_any") and not _contains_any(finding.evidence, condition["evidence_contains_any"]):
        return False
    raw_path = ""
    if isinstance(finding.raw, dict):
        raw_path = str(finding.raw.get("path", ""))
    url_path = urlparse(str(finding.url or "")).path
    if condition.get("raw_path_contains_any") and not _contains_any(raw_path, condition["raw_path_contains_any"]):
        return False
    if condition.get("url_path_contains_any") and not _contains_any(url_path, condition["url_path_contains_any"]):
        return False
    known = {"module", "type", "tag_any", "title_contains_any", "title_requires_any",
             "evidence_contains_any", "raw_path_contains_any", "url_path_contains_any"}
    return bool(set(condition) & known)


def _load_rules(path: Path) -> list[dict]:
    import yaml
    with path.open("r", encoding="utf-8") as stream:
        rules = yaml.safe_load(stream)
    if not isinstance(rules, list):
        raise ValueError("chain rules must be a YAML list")
    valid = []
    for rule in rules[:MAX_RULES]:
        if not isinstance(rule, dict):
            continue
        if not isinstance(rule.get("id"), str) or not isinstance(rule.get("name"), str):
            continue
        conditions = rule.get("when")
        if not isinstance(conditions, list) or not 1 <= len(conditions) <= MAX_CONDITIONS:
            continue
        if not all(isinstance(condition, dict) for condition in conditions):
            continue
        if str(rule.get("severity", "")).lower() not in _VALID_SEVERITIES:
            continue
        if not isinstance(rule.get("narrative"), str):
            continue
        valid.append(rule)
    return valid


def _evaluate(rule: dict, findings: list[Finding]) -> list[Finding] | None:
    selected = []
    used: set[int] = set()
    allow_same = bool(rule.get("allow_same_finding"))
    for condition in rule["when"]:
        match = next((index for index, finding in enumerate(findings)
                      if (allow_same or index not in used) and _matches(finding, condition)), None)
        if match is None:
            return None
        selected.append(findings[match])
        used.add(match)
    return selected


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    del client  # Pure correlation; no HTTP requests are made.
    try:
        import yaml  # noqa: F401
    except ImportError:
        ctx.add(Finding(module=NAME, title="Attack-chain корреляция пропущена: PyYAML не установлен",
                        severity=Severity.INFO, source="optional dependency", confidence="high"))
        return
    try:
        rules = _load_rules(_rules_path(ctx))
    except (OSError, ValueError, TypeError) as exc:
        LOG.warning("attack-chain rules unavailable (%s)", type(exc).__name__)
        ctx.add(Finding(module=NAME, title="Attack-chain rules недоступны",
                        severity=Severity.INFO, description=f"Файл правил не загружен ({type(exc).__name__}).",
                        source="chain rules", confidence="high"))
        return

    base_findings = list(ctx.findings)
    existing_rules = {str(finding.raw.get("rule_id")) for finding in base_findings
                      if finding.type == "attack_chain" and isinstance(finding.raw, dict)}
    emitted = 0
    for rule in rules:
        rule_id = rule["id"][:100]
        if rule_id in existing_rules:
            continue
        matched = _evaluate(rule, base_findings)
        if not matched:
            continue
        ids = list(dict.fromkeys(finding.id for finding in matched))
        titles = list(dict.fromkeys(finding.title[:160] for finding in matched))
        severity = _VALID_SEVERITIES[str(rule["severity"]).lower()]
        ctx.add(Finding(module=NAME, type="attack_chain", title=f"Attack path: {rule['name'][:180]}",
                        severity=severity,
                        evidence="finding_ids=" + ",".join(ids),
                        description=str(rule["narrative"])[:1000],
                        remediation="Проверьте каждую составляющую цепочки, устраните первопричины и повторите сканирование.",
                        source="YAML attack-chain rule", confidence="medium",
                        references=[], tags=["attack-chain", rule_id],
                        raw={"rule_id": rule_id, "finding_ids": ids, "matched_titles": titles,
                             "component_count": len(ids)}))
        existing_rules.add(rule_id)
        emitted += 1
    ctx.add(Finding(module=NAME, title=f"Attack-chain корреляция завершена: правил {len(rules)}, цепочек {emitted}",
                    severity=Severity.INFO, description="Сопоставлены только текущие Findings; сетевые запросы и автоматическая эксплуатация не выполнялись.",
                    source="YAML attack-chain rules", confidence="high",
                    raw={"rules_loaded": len(rules), "chains_emitted": emitted}))
