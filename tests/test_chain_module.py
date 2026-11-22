"""Attack-chain rules are declarative, deterministic, and make no network calls."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import Finding, ScanContext, Severity
from mortyscan.modules import chain


def test_yaml_attack_paths_correlate_findings_and_preserve_component_ids(tmp_path: Path):
    findings = [
        Finding(module="exposures", title="Возможная утечка конфигурации / .env", severity=Severity.HIGH,
                tags=["exposure", ".env"]),
        Finding(module="cors_audit", title="CORS доверяет произвольному Origin с credentials", severity=Severity.HIGH,
                tags=["cors"]),
        Finding(module="jwt", title="JWT: HS256 подписан известным слабым секретом", severity=Severity.CRITICAL),
        Finding(module="discovery", title="Найден путь: /admin (код 200)", severity=Severity.MEDIUM,
                url="https://example.com/admin", raw={"path": "/admin"}),
        Finding(module="js_deep", title="Source map раскрывает исходный код", severity=Severity.HIGH,
                tags=["source-map", "source-code"]),
        Finding(module="js_deep", title="Возможный секрет в JavaScript: API key", severity=Severity.HIGH,
                source="source map", tags=["secret", "javascript", "source-map"]),
        Finding(module="openapi", title="Возможный BOLA/IDOR: аккаунт B прочитал ресурс", severity=Severity.CRITICAL),
    ]
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      findings=findings)

    async def audit():
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: (_ for _ in ()).throw(AssertionError("chain module must be network-free")))) as client:
            await chain.run(ctx, client)

    asyncio.run(audit())
    chains = [finding for finding in ctx.findings if finding.type == "attack_chain"]
    rule_ids = {finding.raw["rule_id"] for finding in chains}
    assert {"env-cors-credentials", "weak-jwt-admin", "source-map-secret", "bola-idor"} <= rule_ids
    assert all(finding.severity == Severity.CRITICAL for finding in chains)
    original_ids = {finding.id for finding in findings}
    assert all(set(finding.raw["finding_ids"]) <= original_ids for finding in chains)
    assert all("finding_ids=" in finding.evidence for finding in chains)
    assert len(chains) == len(rule_ids)


def test_chain_load_failure_is_reported_without_crashing(tmp_path: Path):
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      config={"chain_rules_path": str(tmp_path / "missing.yaml")})
    async def audit():
        async with httpx.AsyncClient() as client:
            await chain.run(ctx, client)
    asyncio.run(audit())
    assert any("rules недоступны" in finding.title for finding in ctx.findings)
