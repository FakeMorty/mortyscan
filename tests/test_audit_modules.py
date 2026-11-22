"""Тесты расширенных CORS и CSRF проверок без внешнего трафика."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext
from mortyscan.modules import cors_audit, csrf_audit


def test_cors_module_probes_known_routes_with_benign_requests(tmp_path: Path):
    requests = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={
            "Access-Control-Allow-Origin": cors_audit.PROBE_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }, request=request)

    async def audit():
        ctx = ScanContext(target="example.test", base_url="https://example.test", case_dir=tmp_path)
        ctx.crawled_urls.update({"https://example.test/api/profile", "https://elsewhere.test/"})
        ctx.endpoints.add("https://example.test/api/new?token=must-not-be-forwarded")
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await cors_audit.run(ctx, client)
        return ctx

    ctx = asyncio.run(audit())
    assert any("CORS доверяет произвольному Origin" in f.title for f in ctx.findings)
    assert all(request.method in {"GET", "OPTIONS"} for request in requests)
    assert all(request.url.host == "example.test" for request in requests)
    assert any(request.url.path == "/api/new" and not request.url.query for request in requests)
    assert not any(request.headers.get("cookie") for request in requests)


def test_csrf_audit_flags_only_state_changing_forms_without_known_tokens(tmp_path: Path):
    async def audit():
        ctx = ScanContext(target="example.test", base_url="https://example.test", case_dir=tmp_path)
        ctx.discovered_forms.extend([
            {"url": "https://example.test/profile", "method": "POST", "inputs": [{"name": "email"}]},
            {"url": "https://example.test/password", "method": "POST", "inputs": [{"name": "csrfmiddlewaretoken"}]},
            {"url": "https://example.test/search", "method": "GET", "inputs": []},
            {"url": "https://other.test/action", "method": "POST", "inputs": []},
        ])
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, request=request)
        )) as client:
            await csrf_audit.run(ctx, client)
        return ctx

    ctx = asyncio.run(audit())
    findings = [f for f in ctx.findings if f.cwe == "CWE-352"]
    assert len(findings) == 1
    assert findings[0].url == "https://example.test/profile"
    assert findings[0].severity.name == "LOW"
