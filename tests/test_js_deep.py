"""JS/source-map analysis tests use only MockTransport responses."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext
from mortyscan.modules import js_deep


def test_js_deep_extracts_endpoints_secrets_and_source_map_without_leaking_values(tmp_path: Path):
    aws_key = "AKIAABCDEFGHIJKLMNOP"
    stripe_key = "sk_live_" + "A" * 28
    jwt = "eyJabcdefghijk.eyJklmnopqrst.abcdefghijk"
    script = (
        f"const access = '{aws_key}';\n"
        f"const stripe = '{stripe_key}';\n"
        f"const token = '{jwt}';\n"
        "fetch('/api/v1/profile');\n"
        "axios.get('api/v1/relative?token=hidden-value');\n"
        "//# sourceMappingURL=app.js.map\n"
    )
    source_map = {
        "version": 3,
        "sources": ["src/app.js"],
        "sourcesContent": ["const password = 'super-secret-value-123456';\nfetch('/api/orders');"],
    }

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("app.js.map"):
            return httpx.Response(200, json=source_map, request=request)
        return httpx.Response(200, text=script, headers={"content-type": "application/javascript"}, request=request)

    async def audit():
        ctx = ScanContext(
            target="example.test", base_url="https://example.test", case_dir=tmp_path,
            config={"save_sourcemaps": True},
        )
        ctx.script_urls.add("https://example.test/assets/app.js")
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await js_deep.run(ctx, client)
        return ctx

    ctx = asyncio.run(audit())
    assert "https://example.test/api/v1/profile" in ctx.endpoints
    assert "https://example.test/assets/api/v1/relative" in ctx.endpoints
    assert all("hidden-value" not in endpoint for endpoint in ctx.endpoints)
    assert "https://example.test/api/orders" in ctx.endpoints
    assert jwt in ctx.seen_jwts
    assert any("Source map раскрывает" in finding.title for finding in ctx.findings)
    assert any("AWS access key" in finding.title for finding in ctx.findings)
    evidence = "\n".join(finding.evidence for finding in ctx.findings)
    assert aws_key not in evidence and stripe_key not in evidence and "super-secret-value" not in evidence
    saved = list((tmp_path / "sourcemaps").glob("*.js"))
    assert len(saved) == 1
    assert saved[0].read_text() == source_map["sourcesContent"][0]


def test_js_deep_filters_documentation_placeholders():
    ctx = ScanContext(target="example.test", base_url="https://example.test")
    js_deep._collect_secrets(ctx, "https://example.test/app.js", "const apiKey='your_key_here';")
    assert not ctx.findings
