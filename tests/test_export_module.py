"""SARIF, diff, and DefectDojo exports are bounded and explicit."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import Finding, ScanContext, Severity
from mortyscan.modules import export
from mortyscan.reporting.report import write_html, write_json


def _finding(title: str, evidence: str, severity: Severity, *, url="https://example.com/api?token=secret") -> Finding:
    return Finding(module="api", type="api_issue", title=title, evidence=evidence,
                   severity=severity, url=url, target="example.com")


def test_sarif_21_uses_finding_type_and_redacts_url_secrets():
    ctx = ScanContext(target="example.com", base_url="https://example.com", findings=[
        _finding("Protected endpoint exposed", "sha evidence", Severity.CRITICAL)])
    sarif = export.build_sarif(ctx)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["results"][0]["ruleId"] == "api_issue"
    assert run["results"][0]["level"] == "error"
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://example.com/api"
    assert "secret" not in json.dumps(sarif)
    assert run["results"][0]["partialFingerprints"]["mortyscan/evidenceHash/v1"]


def test_diff_reports_new_fixed_open_and_regressed_states():
    previous = [
        {"type": "api_issue", "target": "example.com", "evidence": "keep", "severity": "HIGH"},
        {"type": "api_issue", "target": "example.com", "evidence": "worse", "severity": "LOW"},
        {"type": "old_issue", "target": "example.com", "evidence": "gone", "severity": "MEDIUM"},
    ]
    current = [
        _finding("Still open", "keep", Severity.HIGH),
        _finding("Severity increased", "worse", Severity.CRITICAL),
        _finding("New issue", "brand new", Severity.LOW),
    ]
    diff = export.build_diff(current, previous)
    assert diff["counts"] == {"new": 1, "fixed": 1, "still_open": 1, "regressed": 1}


def test_local_sarif_diff_and_versioned_json_html_outputs(tmp_path: Path):
    previous_path = tmp_path / "previous.json"
    previous_path.write_text(json.dumps({"цель": "example.com", "находки": []}), encoding="utf-8")
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      findings=[_finding("Issue", "evidence", Severity.HIGH)],
                      config={"sarif_enabled": True, "diff_from": str(previous_path)})
    async def run():
        async with httpx.AsyncClient() as client:
            await export.run(ctx, client)
    asyncio.run(run())
    payload_path = write_json(ctx, tmp_path / "report.json")
    write_html(ctx, tmp_path / "report.html")
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "2.0"
    assert payload["diff"]["counts"]["new"] == 1
    assert (tmp_path / "report.sarif").is_file()
    assert "Diff сканирований" in (tmp_path / "report.html").read_text(encoding="utf-8")


def test_defectdojo_upload_is_explicit_and_does_not_retain_api_key(tmp_path: Path):
    seen = []
    def handler(request: httpx.Request):
        seen.append(request)
        return httpx.Response(201, json={"status": "created"}, request=request)
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      findings=[_finding("Issue", "evidence", Severity.HIGH)],
                      config={"defectdojo_url": "https://dojo.example", "defectdojo_key": "test-api-secret",
                              "defectdojo_engagement_id": 12,
                              "_defectdojo_test_transport": httpx.MockTransport(handler)})
    async def run():
        async with httpx.AsyncClient() as client:
            await export.run(ctx, client)
    asyncio.run(run())
    request = seen[0]
    assert request.method == "POST"
    assert request.url.path == "/api/v2/import-scan/"
    assert request.headers["authorization"] == "Token test-api-secret"
    assert b"mortyscan.sarif" in request.content and b"SARIF" in request.content
    assert "defectdojo_key" not in ctx.config
    assert "test-api-secret" not in json.dumps([f.to_dict() for f in ctx.findings])


def test_no_external_blocks_defectdojo_upload(tmp_path: Path):
    def handler(request: httpx.Request):
        raise AssertionError("--no-external must not make requests")
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      config={"defectdojo_url": "https://dojo.example", "defectdojo_key": "test-key",
                              "defectdojo_engagement_id": 2, "no_external": True,
                              "_defectdojo_test_transport": httpx.MockTransport(handler)})
    async def run():
        async with httpx.AsyncClient() as client:
            await export.run(ctx, client)
    asyncio.run(run())
    assert "defectdojo_key" not in ctx.config
    assert any("пропущен (--no-external)" in finding.title for finding in ctx.findings)
