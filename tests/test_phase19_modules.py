"""Focused mocked tests for the v19.1 module tranche."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext, make_client
from mortyscan.modules import cors_audit, exposures, redirect, waf


def test_exposures_uses_baseline_and_signatures(tmp_path: Path):
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n", request=request)
        return httpx.Response(404, text="not found", request=request)

    async def audit():
        ctx = ScanContext(target="example.test", base_url="https://example.test", case_dir=tmp_path,
                          permissions={"intrusive": True}, config={"exposure_max_paths": 1, "rate_limit": 1000})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await exposures.run(ctx, client)
        return ctx

    ctx = asyncio.run(audit())
    assert any("Git" in f.title and f.severity.name == "HIGH" for f in ctx.findings)


def test_exposures_filters_matching_soft404_signature(tmp_path: Path):
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ref: refs/heads/main\n", request=request)

    async def audit():
        ctx = ScanContext(target="example.test", base_url="https://example.test", case_dir=tmp_path,
                          permissions={"intrusive": True}, config={"exposure_max_paths": 1, "rate_limit": 1000})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await exposures.run(ctx, client)
        return ctx

    ctx = asyncio.run(audit())
    assert not any(f.severity.name == "HIGH" for f in ctx.findings)


def test_redirect_does_not_follow_external_redirect(tmp_path: Path):
    requested = []

    def respond(request: httpx.Request) -> httpx.Response:
        requested.append(request)
        return httpx.Response(302, headers={"Location": "https://evil.mortyscan.invalid/"}, request=request)

    async def audit():
        ctx = ScanContext(target="example.test", base_url="https://example.test", case_dir=tmp_path,
                          permissions={"intrusive": True},
                          config={"redirect_max_requests": 1, "rate_limit": 1000})
        ctx.crawled_urls.add("https://example.test/?next=home")
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await redirect.run(ctx, client)
        return ctx

    ctx = asyncio.run(audit())
    assert any("Open Redirect" in f.title for f in ctx.findings)
    assert len(requested) == 1
    assert requested[0].method == "GET"


def test_waf_is_passively_fingerprinted(tmp_path: Path):
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Server": "cloudflare", "CF-Ray": "abc"}, request=request)

    async def audit():
        ctx = ScanContext(target="example.test", base_url="https://example.test", case_dir=tmp_path)
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await waf.run(ctx, client)
        return ctx

    ctx = asyncio.run(audit())
    assert ctx.waf and ctx.waf[0]["name"] == "Cloudflare"


def test_waf_tamper_chains_match_documented_mapping():
    assert waf.get_tamper_chain("Cloudflare") == ["between", "randomcase", "space2comment"]
    assert waf.get_tamper_chain("ModSecurity") == ["space2comment", "percentage", "randomcase"]
    assert waf.get_tamper_chain("Akamai") == ["charencode", "randomcase"]
    assert waf.get_tamper_chain("F5 BIG-IP") == ["between", "charencode"]
    assert waf.get_tamper_chain("unknown") == ["space2comment"]


def test_scope_allowlist_supports_domains_wildcards_and_cidrs():
    from mortyscan.core import host_in_scope
    assert host_in_scope("example.test", {"example.test"})
    assert host_in_scope("api.example.test", {"example.test"})
    assert host_in_scope("api.example.test", {"*.example.test"})
    assert not host_in_scope("example.test", {"*.example.test"})
    assert host_in_scope("192.0.2.15", {"192.0.2.0/24"})
    assert not host_in_scope("198.51.100.1", {"192.0.2.0/24"})


def test_http_client_blocks_out_of_scope_request_before_network():
    seen = []
    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        return httpx.Response(200, request=request)

    async def invoke():
        async with make_client(
            scope_hosts={"example.test"}, transport=httpx.MockTransport(respond)
        ) as client:
            await client.get("https://example.test/in-scope")
            try:
                await client.get("https://outside.test/blocked")
            except httpx.RequestError:
                pass
            else:
                raise AssertionError("out-of-scope request was not rejected")
    asyncio.run(invoke())
    assert seen == ["example.test"]


def test_auth_headers_are_not_sent_outside_target_host():
    received = []

    def respond(request: httpx.Request) -> httpx.Response:
        received.append((request.url.host + request.url.path, request.headers.get("authorization")))
        return httpx.Response(200, request=request)

    async def invoke():
        async with make_client(
            extra_headers={"Authorization": "Bearer secret", "X-Audit": "yes"},
            auth_origin="https://example.test",
            transport=httpx.MockTransport(respond),
        ) as client:
            await client.get("https://example.test/path")
            await client.get("http://example.test:80/path")
            await client.get("https://metadata.invalid/path")
    asyncio.run(invoke())
    assert received == [
        ("example.test/path", "Bearer secret"),
        ("example.test/path", None),
        ("metadata.invalid/path", None),
    ]
