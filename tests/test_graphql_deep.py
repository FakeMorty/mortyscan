"""GraphQL deep probes use only MockTransport and never issue mutations."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext
from mortyscan.modules import graphql_deep


def test_graphql_type_wordlist_and_field_suggestions_are_bounded(tmp_path: Path):
    requests = []
    def handler(request: httpx.Request):
        requests.append(request)
        if request.url.path != "/graphql":
            return httpx.Response(404, request=request)
        query = json.loads(request.content.decode())["query"]
        if "__typename" in query:
            return httpx.Response(200, json={"data": {"__typename": "Query"}}, request=request)
        if "__schema" in query:
            return httpx.Response(400, json={"errors": [{"message": "Introspection is disabled"}]}, request=request)
        if 'name: "User"' in query:
            return httpx.Response(200, json={"data": {"__type": {"name": "User", "fields": [{"name": "email"}]}}}, request=request)
        return httpx.Response(400, json={"errors": [{"message": "Unknown field. Did you mean 'email'?"}]}, request=request)

    async def audit():
        ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                          config={"graphql_deep_enabled": True}, permissions={"intrusive": True})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await graphql_deep.run(ctx, client)
        return ctx
    ctx = asyncio.run(audit())
    assert ctx.config["graphql_type_names"] == ["User"]
    assert "email" in ctx.config["graphql_field_suggestions"]
    assert any(f.source == "GraphQL type probes" for f in ctx.findings)
    assert len(requests) <= 40
    assert not any(json.loads(request.content.decode())["query"].lstrip().lower().startswith("mutation") for request in requests)


def test_graphql_batch_probe_needs_runtime_permission_and_explicit_flag(tmp_path: Path):
    requests = []
    def handler(request: httpx.Request):
        requests.append(request)
        if request.url.path != "/graphql":
            return httpx.Response(404, request=request)
        query = request.content.decode()
        if "__typename" in query:
            return httpx.Response(200, json={"data": {"__typename": "Query"}}, request=request)
        return httpx.Response(400, json={"errors": [{"message": "disabled"}]}, request=request)
    async def audit():
        ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                          config={"graphql_deep_enabled": True, "graphql_load_tests": True,
                                  "graphql_load_tests_confirmed": True},
                          permissions={"intrusive": True})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await graphql_deep.run(ctx, client)
        return ctx
    ctx = asyncio.run(audit())
    assert any("batch из 100" in f.title for f in ctx.findings)
    assert any("a99" in request.content.decode() for request in requests)


def test_graphql_batch_flag_without_tty_confirmation_is_skipped(tmp_path: Path):
    requests = []
    def handler(request: httpx.Request):
        requests.append(request)
        if request.url.path != "/graphql":
            return httpx.Response(404, request=request)
        return httpx.Response(200, json={"data": {"__typename": "Query"}}, request=request)
    async def audit():
        ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                          config={"graphql_deep_enabled": True, "graphql_load_tests": True},
                          permissions={"intrusive": True})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await graphql_deep.run(ctx, client)
        return ctx
    ctx = asyncio.run(audit())
    assert not any("a99" in request.content.decode() for request in requests)
    assert any("нет TTY-подтверждения" in f.title for f in ctx.findings)
