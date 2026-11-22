"""OAST is opt-in, read-only by default, scope-filtered, and managed by a tool session."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext, Severity
from mortyscan.modules import oast
from mortyscan.cli import app


def test_oast_helpers_validate_server_and_match_generated_payloads(tmp_path: Path):
    assert oast._server_name("https://collaborator.example/path") == "collaborator.example"
    assert oast._server_name("collaborator.example") == "collaborator.example"
    try:
        oast._server_name("https://user:pass@collaborator.example")
    except ValueError:
        pass
    else:
        raise AssertionError("OAST URL credentials must be rejected")

    payload_file = tmp_path / "payloads.txt"
    payload_file.write_text("abc123.oast.example\nnot a host with spaces\n", encoding="utf-8")
    assert oast._payload_hosts(payload_file, 5) == ["abc123.oast.example"]
    ctx = ScanContext(target="example.com", base_url="https://example.com", crawled_urls={
        "https://example.com/search?q=old"}, discovered_params={"/search": {"q"}})
    probes = oast._candidate_probes(ctx)
    assert [probe["kind"] for probe in probes] == ["parameter", "X-Forwarded-Host", "Host"]
    ctx.discovered_forms = [
        {"url": "https://example.com/settings", "method": "POST", "inputs": [{"name": "webhook_url"}]},
        {"url": "https://example.com/import", "method": "POST", "inputs": [{"name": "file"}]},
        {"url": "https://outside.test/collect", "method": "POST", "inputs": [{"name": "webhook"}]},
    ]
    write_probes = oast._candidate_write_probes(ctx)
    assert [probe["kind"] for probe in write_probes] == ["webhook-json", "xml-xxe"]
    assert all(oast._in_scope(ctx, probe["url"]) for probe in write_probes)


def test_oast_write_probes_require_separate_interactive_confirmation():
    result = CliRunner().invoke(app, ["scan", "example.com", "--active", "--oast", "--oast-write-probes",
                                     "--yes", "--i-own-this-target"])
    assert result.exit_code == 2
    assert "неинтерактивном режиме" in result.output


def test_oast_full_flow_uses_scoped_gets_and_confirmed_callback(tmp_path: Path, monkeypatch):
    seen = []
    interaction_path = None
    async def handler(request: httpx.Request):
        seen.append(request)
        query = request.url.query.decode()
        host_header = request.headers.get("host", "")
        forwarded_host = request.headers.get("x-forwarded-host", "")
        body = request.content.decode("utf-8", errors="replace")
        candidate = next((f"canary{i}" for i in range(1, 6)
                          if f"canary{i}" in query or f"canary{i}" in host_header
                          or f"canary{i}" in forwarded_host or f"canary{i}" in body), None)
        if candidate and interaction_path:
            with interaction_path.open("a", encoding="utf-8") as stream:
                stream.write('{"protocol":"DNS","full-id":"' + candidate + '.oast.test"}\n')
        return httpx.Response(200, text="ok", request=request)

    class FakeSession:
        returncode = None
        async def __aenter__(self):
            return self
        async def __aexit__(self, *_):
            self.returncode = 0
        async def close(self):
            self.returncode = 0

    async def fake_start(command, **kwargs):
        nonlocal interaction_path
        payload_path = Path(command[command.index("-psf") + 1])
        interaction_path = Path(command[command.index("-o") + 1])
        count = int(command[command.index("-n") + 1])
        payload_path.write_text("".join(f"canary{i + 1}.oast.test\n" for i in range(count)), encoding="utf-8")
        interaction_path.write_text("", encoding="utf-8")
        return FakeSession()

    monkeypatch.setattr(oast, "start_tool_session", fake_start)
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      crawled_urls={"https://example.com/search?q=old"},
                      discovered_params={"/search": {"q"}},
                      discovered_forms=[
                          {"url": "https://example.com/settings", "method": "POST", "inputs": [{"name": "webhook_url"}]},
                          {"url": "https://example.com/import", "method": "POST", "inputs": [{"name": "file"}]},
                      ],
                      config={"oast_enabled": True, "oast_write_probes": True,
                              "oast_write_confirmed": True, "interactsh_url": ""},
                      permissions={"intrusive": True})
    async def audit():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await oast.run(ctx, client)
    asyncio.run(audit())
    findings = [finding for finding in ctx.findings if finding.confidence == "confirmed"]
    assert findings
    assert all(f.severity == Severity.HIGH for f in findings)
    assert all("canary" not in f.evidence and "canary" not in f.url for f in findings)
    assert all(request.url.host == "example.com" for request in seen)
    assert any(request.url.params.get("q", "").startswith("canary") for request in seen)
    posts = [request for request in seen if request.method == "POST"]
    assert len(posts) == 2
    assert {request.headers.get("content-type", "").split(";")[0] for request in posts} == {
        "application/json", "application/xml"}
    assert any("blind XXE" in finding.title for finding in findings)


def test_oast_no_external_gate_does_not_launch_client(tmp_path: Path, monkeypatch):
    async def fail(*args, **kwargs):
        raise AssertionError("must not start OAST tool")
    monkeypatch.setattr(oast, "start_tool_session", fail)
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      config={"oast_enabled": True, "no_external": True},
                      permissions={"intrusive": True})
    async def audit():
        async with httpx.AsyncClient() as client:
            await oast.run(ctx, client)
    asyncio.run(audit())
    assert any("--no-external" in finding.title for finding in ctx.findings)
