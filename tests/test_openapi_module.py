"""OpenAPI probes are constrained to mocked same-origin read-only requests."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext
from mortyscan.modules import openapi


def test_openapi_discovers_schema_and_detects_protected_endpoint_without_auth(tmp_path: Path):
    spec = {"openapi": "3.0.3", "security": [{"bearerAuth": []}],
            "paths": {"/api/private": {"get": {"responses": {"200": {"description": "ok"}}}}}}
    requests = []
    def handler(request: httpx.Request):
        requests.append(request)
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=spec, request=request)
        if request.url.path == "/api/private":
            return httpx.Response(200, json={"ok": True}, request=request)
        return httpx.Response(404, request=request)
    async def audit():
        ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                          config={"openapi_enabled": True}, permissions={"intrusive": True})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await openapi.run(ctx, client)
        return ctx
    ctx = asyncio.run(audit())
    assert any("auth bypass" in f.title for f in ctx.findings)
    assert any(f.title.startswith("OpenAPI-аудит завершён") for f in ctx.findings)
    assert all(request.url.host == "example.com" for request in requests)
    anonymous = [request for request in requests if request.url.path == "/api/private" and not request.headers.get("authorization")]
    assert anonymous
    assert not any(request.method in {"POST", "PUT", "PATCH", "DELETE"} for request in requests)


def test_openapi_bola_uses_isolated_accounts_and_reports_only_hashes(tmp_path: Path):
    spec = {"openapi": "3.0.3", "paths": {"/api/users/{id}": {
        "get": {"parameters": [{"name": "id", "in": "path", "required": True,
                                 "schema": {"type": "integer", "example": 7}}],
               "responses": {"200": {"description": "user"}}}}}}
    seen = []
    def handler(request: httpx.Request):
        seen.append((request.url.path, request.headers.get("cookie", "")))
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=spec, request=request)
        if request.url.path == "/api/users/7":
            return httpx.Response(200, json={"id": 7, "private": "not-in-report"}, request=request)
        return httpx.Response(404, request=request)
    async def audit():
        ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                          config={"openapi_enabled": True}, permissions={"intrusive": True},
                          auth={"a": {"cookie": "session=A", "headers": {}},
                                "b": {"cookie": "session=B", "headers": {}}})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await openapi.run(ctx, client)
        return ctx
    ctx = asyncio.run(audit())
    bola = next(f for f in ctx.findings if "BOLA/IDOR" in f.title)
    assert bola.severity.name == "CRITICAL"
    assert "not-in-report" not in bola.evidence
    assert {cookie for path, cookie in seen if path == "/api/users/7"} >= {"session=A", "session=B", ""}
    assert "https://example.com/api/users/7" in ctx.endpoints
