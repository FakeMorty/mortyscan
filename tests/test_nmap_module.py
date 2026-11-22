"""Nmap integration parses bounded XML and only invokes the async wrapper when opted in."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext, Severity
from mortyscan.modules import ports
from mortyscan.tools.runner import ToolNotFound, ToolResult


def test_nmap_xml_finds_open_services_and_cve_without_raw_script_output(tmp_path: Path):
    ctx = ScanContext(target="127.0.0.1", base_url="https://127.0.0.1", case_dir=tmp_path, ip="127.0.0.1")
    xml = '''<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.25"/>
      <script id="ssl-heartbleed" output="VULNERABLE CVE-2014-0160 leaked-secret"/></port>
    </ports></host><host><address addr="203.0.113.99" addrtype="ipv4"/><ports>
      <port protocol="tcp" portid="22"><state state="open"/></port>
    </ports></host></nmaprun>'''
    count = ports._parse_nmap_xml(ctx, xml)
    assert count == 2
    service = next(f for f in ctx.findings if "open 443" in f.title)
    nse = next(f for f in ctx.findings if f.source == "Nmap NSE")
    assert "nginx 1.25" in service.title
    assert nse.severity == Severity.HIGH
    assert nse.raw["cves"] == ["CVE-2014-0160"]
    assert "leaked-secret" not in nse.evidence and "leaked-secret" not in nse.description


def test_nmap_uses_wrapper_only_after_explicit_opt_in(tmp_path: Path, monkeypatch):
    calls = []
    async def fake_run_tool(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return ToolResult(command=cmd, returncode=0, stdout="<nmaprun><host><ports/></host></nmaprun>",
                          stderr="", duration=0.01)
    monkeypatch.setattr(ports, "run_tool", fake_run_tool)
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      ip="192.0.2.10", config={"nmap_enabled": True, "rate_limit": 10},
                      permissions={"intrusive": True})
    async def audit():
        await ports._run_nmap(ctx, "192.0.2.10")
    asyncio.run(audit())
    assert calls
    command, kwargs = calls[0]
    assert command[0] == "nmap" and "-oX" in command and "--top-ports" in command
    assert command[-1] == "192.0.2.10"
    assert kwargs["timeout"] <= 900
    assert any("Nmap завершён" in finding.title for finding in ctx.findings)

    out_of_scope = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                               config={"nmap_enabled": True, "scope_hosts": ["elsewhere.com"]},
                               permissions={"intrusive": True})
    asyncio.run(ports._run_nmap(out_of_scope, "192.0.2.10"))
    assert len(calls) == 1
    assert any("вне scope" in finding.title for finding in out_of_scope.findings)


def test_nmap_gracefully_skips_missing_binary_and_no_external(tmp_path: Path, monkeypatch):
    async def missing(*args, **kwargs):
        raise ToolNotFound("nmap")
    monkeypatch.setattr(ports, "run_tool", missing)
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      config={"nmap_enabled": True}, permissions={"intrusive": True})
    asyncio.run(ports._run_nmap(ctx, "192.0.2.10"))
    assert any("не установлен" in finding.title for finding in ctx.findings)

    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      config={"nmap_enabled": True, "no_external": True},
                      permissions={"intrusive": True})
    asyncio.run(ports._run_nmap(ctx, "192.0.2.10"))
    assert any("--no-external" in finding.title for finding in ctx.findings)
