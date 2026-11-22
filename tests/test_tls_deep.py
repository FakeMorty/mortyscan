"""SSLyze result mapping is tested without network access or the optional package."""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext, Severity
from mortyscan.modules import tls_deep


def _attempt(result):
    return SimpleNamespace(status="COMPLETED", result=result)


def test_sslyze_findings_cover_legacy_protocols_weak_ciphers_heartbleed_and_chain():
    unsupported = SimpleNamespace(is_tls_version_supported=False, accepted_cipher_suites=[])
    ssl3 = SimpleNamespace(is_tls_version_supported=True, accepted_cipher_suites=[])
    tls12 = SimpleNamespace(is_tls_version_supported=True, accepted_cipher_suites=[
        SimpleNamespace(cipher_suite=SimpleNamespace(name="TLS_RSA_WITH_3DES_EDE_CBC_SHA", key_size=112))])
    leaf = SimpleNamespace(not_valid_after_utc=datetime.now(timezone.utc) - timedelta(days=3))
    deployment = SimpleNamespace(received_certificate_chain=[leaf], path_validation_results=[
        SimpleNamespace(was_validation_successful=False)],
        leaf_certificate_has_must_staple_extension=True, ocsp_response=None)
    scan = SimpleNamespace(scan_result=SimpleNamespace(
        ssl_2_0_cipher_suites=_attempt(unsupported), ssl_3_0_cipher_suites=_attempt(ssl3),
        tls_1_0_cipher_suites=_attempt(unsupported), tls_1_1_cipher_suites=_attempt(unsupported),
        tls_1_2_cipher_suites=_attempt(tls12), tls_1_3_cipher_suites=_attempt(unsupported),
        heartbleed=_attempt(SimpleNamespace(is_vulnerable_to_heartbleed=True)),
        robot=_attempt(SimpleNamespace(robot_result="VULNERABLE_STRONG_ORACLE")),
        certificate_info=_attempt(SimpleNamespace(certificate_deployments=[deployment])),
        http_headers=_attempt(SimpleNamespace(strict_transport_security_header=None))))
    ctx = ScanContext(target="example.com", base_url="https://example.com")
    count = tls_deep._consume_result(ctx, scan)
    titles = [finding.title for finding in ctx.findings]
    assert count >= 7
    assert any("POODLE" in title for title in titles)
    assert any("слабые шифры" in title for title in titles)
    assert any("Heartbleed" in title for title in titles)
    assert any("ROBOT" in title for title in titles)
    assert any("expired" in title for title in titles)
    assert any("chain validation" in title for title in titles)
    assert any("Must-Staple" in title for title in titles)
    assert any("HSTS" in title for title in titles)


def test_tls_deep_gracefully_skips_missing_optional_sslyze(tmp_path: Path, monkeypatch):
    monkeypatch.setitem(sys.modules, "sslyze", None)
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      config={"tls_deep_enabled": True}, permissions={"intrusive": True})
    async def audit():
        async with httpx.AsyncClient() as client:
            await tls_deep.run(ctx, client)
    asyncio.run(audit())
    assert any("не установлен" in finding.title for finding in ctx.findings)


def test_tls_deep_inactive_http_target_does_not_load_scanner(tmp_path: Path):
    ctx = ScanContext(target="example.com", base_url="http://example.com", case_dir=tmp_path,
                      config={"tls_deep_enabled": True}, permissions={"intrusive": True})
    async def audit():
        async with httpx.AsyncClient() as client:
            await tls_deep.run(ctx, client)
    asyncio.run(audit())
    assert any("не HTTPS" in finding.title for finding in ctx.findings)


def test_tls_deep_respects_no_external_and_scope_gates(tmp_path: Path):
    async def run_with(config):
        ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                          config={"tls_deep_enabled": True, **config},
                          permissions={"intrusive": True})
        async with httpx.AsyncClient() as client:
            await tls_deep.run(ctx, client)
        return ctx.findings
    assert any("--no-external" in item.title for item in asyncio.run(run_with({"no_external": True})))
    assert any("вне scope" in item.title for item in asyncio.run(run_with({"scope_hosts": ["other.example"]})))
