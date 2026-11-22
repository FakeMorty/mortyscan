"""Auth bootstrap is exercised entirely with an in-memory HTTPX transport."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext, make_client, same_origin
from mortyscan.modules import auth
from mortyscan.reporting.report import write_json


def test_form_login_exports_isolated_account_sessions_without_leaking_credentials(tmp_path: Path):
    seen = []
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.headers.get("cookie", "")))
        if request.url.path == "/login" and request.method == "GET":
            return httpx.Response(200, text=(
                '<form method="post" action="/session"><input type="hidden" name="csrf" value="n1">'
                '<input type="email" name="email"><input type="password" name="password"></form>'
            ), request=request)
        if request.url.path == "/session" and request.method == "POST":
            body = request.content.decode()
            account = "B" if "user_b" in body else "A"
            return httpx.Response(200, json={"access_token": f"token-{account}"},
                                  headers={"set-cookie": f"session={account}; Path=/; HttpOnly"}, request=request)
        if request.url.path in {"/", "/profile"}:
            return httpx.Response(200 if "session=" in request.headers.get("cookie", "") else 401,
                                  request=request)
        return httpx.Response(404, request=request)

    async def audit():
        ctx = ScanContext(
            target="example.com", base_url="https://example.com", case_dir=tmp_path,
            config={"login_url": "https://example.com/login", "login_creds": "user_a:pass-A-secret",
                    "account_b": "user_b:pass-B-secret", "request_headers": ["X-Custom: test"]},
        )
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await auth.run(ctx, client)
            primary_headers = dict(client.headers)
        return ctx, primary_headers

    ctx, primary_headers = asyncio.run(audit())
    assert ctx.auth["a"]["cookie"] == "session=A"
    assert ctx.auth["b"]["cookie"] == "session=B"
    assert ctx.auth["a"]["headers"]["Authorization"] == "Bearer token-A"
    assert ctx.auth["b"]["headers"]["Authorization"] == "Bearer token-B"
    assert primary_headers["cookie"] == "session=A"
    assert "pass-A-secret" not in json.dumps([finding.to_dict() for finding in ctx.findings])
    assert "pass-B-secret" not in json.dumps([finding.to_dict() for finding in ctx.findings])
    assert "login_creds" not in ctx.config and "account_b" not in ctx.config
    report = write_json(ctx, tmp_path / "auth-report.json").read_text()
    assert "pass-A-secret" not in report and "pass-B-secret" not in report
    # Each verification used only that account's own session.
    assert [cookie for method, path, cookie in seen if path == "/"] == ["session=A", "session=B"]


def test_authenticated_headers_are_removed_on_other_origins():
    observed = {}
    def handler(request: httpx.Request) -> httpx.Response:
        observed[request.url.host] = dict(request.headers)
        return httpx.Response(200, request=request)

    async def audit():
        async with make_client(
            extra_headers={"X-Api-Key": "secret", "Cookie": "sid=secret"},
            auth_origin="https://example.com", scope_hosts={"example.com"},
            transport=httpx.MockTransport(handler),
        ) as client:
            client.headers["Authorization"] = "Bearer dynamic-secret"
            await client.get("https://example.com/private")
            await client.get("https://api.example.com/public")

    asyncio.run(audit())
    assert observed["example.com"]["x-api-key"] == "secret"
    assert observed["example.com"]["cookie"] == "sid=secret"
    assert observed["example.com"]["authorization"] == "Bearer dynamic-secret"
    for name in ("x-api-key", "cookie", "authorization", "proxy-authorization"):
        assert name not in observed["api.example.com"]


def test_same_origin_checks_scheme_host_and_port():
    assert same_origin("https://example.com/a", "https://example.com")
    assert not same_origin("http://example.com/a", "https://example.com")
    assert not same_origin("https://api.example.com/a", "https://example.com")
    assert not same_origin("https://example.com:8443/a", "https://example.com")
