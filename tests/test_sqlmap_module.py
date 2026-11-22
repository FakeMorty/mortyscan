"""SQLMap adapter tests must never start a real external scanner."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext
from mortyscan.modules import sqlmap
from mortyscan.tools.runner import ToolResult


def _ctx(tmp_path: Path, **config) -> ScanContext:
    candidates = config.pop("sqli_findings", [{"url": "https://example.com/item?id=1", "method": "GET",
                                                "param": "id", "base_params": {"id": "1"}, "post": False,
                                                "dbms_hint": ""}])
    base = {"sqlmap_enabled": True}
    base.update(config)
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path, config=base,
                      permissions={"intrusive": True})
    ctx.sqli_candidates = candidates
    return ctx


def test_sqlmap_safe_mode_and_aggressive_never_dump(tmp_path: Path, monkeypatch):
    calls = []
    async def fake_run(args, *, timeout):
        calls.append((args, timeout))
        return ToolResult(args, 0, "Parameter: id (GET)\nType: boolean-based blind\nTitle: AND boolean-based blind", "", 0.1)
    monkeypatch.setattr(sqlmap, "run_tool", fake_run)
    async def run_config(**config):
        ctx = _ctx(tmp_path, **config)
        await sqlmap.run(ctx, None)
        return ctx
    normal = asyncio.run(run_config())
    aggressive = asyncio.run(run_config(aggressive=True))
    assert calls[0][1] == 180
    assert "--level=2" in calls[0][0] and "--risk=2" in calls[0][0]
    assert "--dump" not in calls[0][0]
    assert "--level=4" in calls[1][0] and "--technique=BEUSTQ" in calls[1][0]
    assert "--dump" not in calls[1][0]
    assert any(f.severity.name == "CRITICAL" for f in normal.findings)
    assert any(f.severity.name == "CRITICAL" for f in aggressive.findings)


def test_sqlmap_runs_only_confirmed_candidates_and_blacklists_paths(tmp_path: Path, monkeypatch):
    calls = []
    async def fake_run(args, *, timeout):
        calls.append(args)
        return ToolResult(args, 0, "", "", 0.1)
    monkeypatch.setattr(sqlmap, "run_tool", fake_run)
    ctx = _ctx(tmp_path, sqli_findings=[
        {"url": "https://example.com/account/delete?id=1", "method": "GET", "param": "id", "base_params": {}, "post": False},
        {"url": "https://outside.example.net/?id=1", "method": "GET", "param": "id", "base_params": {}, "post": False},
    ], scope_hosts=["example.com"])
    asyncio.run(sqlmap.run(ctx, None))
    assert calls == []
    assert any("destructive-like" in f.title for f in ctx.findings)


def test_sqlmap_dump_requires_confirmed_and_extra_cannot_enable_dump(tmp_path: Path, monkeypatch):
    calls = []
    async def fake_run(args, *, timeout):
        calls.append(args)
        return ToolResult(args, 0, "", "", 0.1)
    monkeypatch.setattr(sqlmap, "run_tool", fake_run)
    ctx = _ctx(tmp_path, dump_data=True, dump_data_confirmed=False)
    asyncio.run(sqlmap.run(ctx, None))
    assert calls == []
    confirmed = _ctx(tmp_path, dump_data=True, dump_data_confirmed=True)
    asyncio.run(sqlmap.run(confirmed, None))
    assert len(calls) == 1 and "--dump" in calls[0]
    assert calls[0].count("--output-dir") == 1
    with pytest.raises(ValueError):
        sqlmap._extra_args(_ctx(tmp_path, sqlmap_extra="--dump"))


def test_sqlmap_waf_headers_and_cookies_are_passed_via_args_and_redacted(tmp_path: Path):
    from mortyscan.tools.runner import _safe_command
    args = ["sqlmap", "--cookie", "session=secret", "--headers", "Authorization: Bearer secret",
            "https://example.com/item?id=secret-value"]
    safe = _safe_command(args)
    assert "session=secret" not in safe and "Bearer secret" not in safe
    assert "secret-value" not in safe
    ctx = _ctx(tmp_path)
    ctx.waf = [{"name": "Cloudflare"}]
    assert sqlmap._waf_tamper(ctx) == "between,randomcase,space2comment"
