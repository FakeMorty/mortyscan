"""Optional phase-2 integrations are mocked and never invoke real scanners/browser."""
from __future__ import annotations

import asyncio
import builtins
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext
from mortyscan.modules import browser, dalfox
from mortyscan.tools.runner import ToolResult


def test_dalfox_only_runs_candidates_and_parses_findings(tmp_path: Path, monkeypatch):
    calls = []
    async def fake_run(args, *, timeout):
        calls.append(args)
        return ToolResult(args, 0, json.dumps({"type": "DOM", "param": "q", "data": args[2]}), "", 0.1)
    monkeypatch.setattr(dalfox, "run_tool", fake_run)
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      config={"dalfox_enabled": True}, permissions={"intrusive": True})
    ctx.xss_candidates = [{"url": "https://example.com/search?q=x", "param": "q", "method": "GET"}]
    asyncio.run(dalfox.run(ctx, None))
    assert len(calls) == 1
    assert calls[0][:3] == ["dalfox", "url", "https://example.com/search?q=x"]
    assert "--deep-domxss" in calls[0]
    assert any(f.module == "dalfox" and f.severity.name == "HIGH" for f in ctx.findings)


def test_dalfox_skips_waf_without_aggressive(tmp_path: Path, monkeypatch):
    async def unexpected(*args, **kwargs):
        raise AssertionError("must not launch against WAF without --aggressive")
    monkeypatch.setattr(dalfox, "run_tool", unexpected)
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      config={"dalfox_enabled": True}, permissions={"intrusive": True})
    ctx.xss_candidates = [{"url": "https://example.com/?q=x"}]
    ctx.waf = [{"name": "Cloudflare"}]
    asyncio.run(dalfox.run(ctx, None))
    assert any("обнаружен WAF" in f.title for f in ctx.findings)


def test_browser_payload_url_and_optional_dependency_skip(tmp_path: Path, monkeypatch):
    item = {"url": "https://example.com/find?q=original", "method": "GET", "param": "q"}
    test_url = browser._page_url_with_payload(item)
    assert "%3Cscript%3Ealert%281%29%3C%2Fscript%3E" in test_url
    original_import = builtins.__import__
    def no_playwright(name, *args, **kwargs):
        if name.startswith("playwright"):
            raise ImportError("playwright not installed")
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", no_playwright)
    ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                      config={"browser_enabled": True}, permissions={"intrusive": True})
    asyncio.run(browser.run(ctx, None))
    assert any("не установлен" in f.title for f in ctx.findings)
