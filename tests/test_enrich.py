"""Enrichment sends only public identifiers and package coordinates to mocked APIs."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import Finding, ScanContext, Severity
from mortyscan.modules import enrich


def test_enrich_attaches_epss_kev_and_osv_with_bounded_disclosure(tmp_path: Path):
    external_requests = []
    def external_handler(request: httpx.Request):
        external_requests.append(request)
        if request.url.host == "api.first.org":
            cve = request.url.params.get("cve", "").split(",")[0]
            return httpx.Response(200, json={"data": [{"cve": cve, "epss": "0.73", "percentile": "0.91"}]}, request=request)
        if request.url.host == "www.cisa.gov":
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}, request=request)
        if request.url.host == "api.osv.dev":
            return httpx.Response(200, json={"vulns": [{"id": "GHSA-test", "summary": "test advisory",
                                                          "details": "CVE-2025-55555"}]}, request=request)
        return httpx.Response(404, request=request)

    def target_handler(request: httpx.Request):
        assert request.url.host == "example.com"
        assert request.url.path == "/package.json"
        return httpx.Response(200, json={"dependencies": {"sample-pkg": "^1.2.3"}}, request=request)

    async def audit():
        ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                          findings=[
                              Finding(module="tech", title="CVE-2024-12345 affects product", severity=Severity.HIGH,
                                      cvss=8.0, raw={"cves": [{"id": "CVE-2024-12345"}]}),
                              Finding(module="exposures", title="Public package.json", severity=Severity.LOW,
                                      url="https://example.com/package.json"),
                          ],
                          config={"enrich_enabled": True, "enrich_cache_dir": str(tmp_path / "cache"),
                                  "_enrich_test_transport": httpx.MockTransport(external_handler)})
        async with httpx.AsyncClient(transport=httpx.MockTransport(target_handler),
                                     headers={"Authorization": "Bearer target-secret"}) as client:
            await enrich.run(ctx, client)
        return ctx

    ctx = asyncio.run(audit())
    enriched = ctx.findings[0].raw["enrichment"]
    assert enriched["cves"]["CVE-2024-12345"] == {"epss": 0.73, "percentile": 0.91, "in_kev": True}
    osv_finding = next(f for f in ctx.findings if f.source == "OSV query")
    assert "sample-pkg@1.2.3" in osv_finding.raw["package"]
    assert "CVE-2025-55555" in osv_finding.evidence
    assert all(request.url.host != "example.com" for request in external_requests)
    assert all("target-secret" not in request.headers.get("authorization", "") for request in external_requests)
    assert all("example.com" not in request.url.query.decode() for request in external_requests)
    assert any((tmp_path / "cache").glob("*.json"))


def test_manifest_parser_ignores_unpinned_requirements():
    parsed = enrich._dependencies_from_manifest("requirements.txt", "requests==2.32.0\nflask>=3.0\n# comment\n")
    assert parsed == [("PyPI", "requests", "2.32.0")]
