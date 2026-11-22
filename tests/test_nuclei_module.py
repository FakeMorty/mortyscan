"""Nuclei wrapper adapter tests; never invokes the real binary."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext
from mortyscan.modules import nuclei
from mortyscan.tools.runner import ToolResult


def test_nuclei_parses_jsonl_deduplicates_and_uses_safe_defaults(tmp_path: Path, monkeypatch):
    commands = []
    record = {
        "template-id": "test-cve",
        "info": {"name": "Test finding", "severity": "high", "tags": ["cve"]},
        "matched-at": "https://example.test/path",
        "matcher-name": "body",
        "extracted-results": ["safe detail"],
        "curl-command": "curl -H 'Authorization: Bearer secret' https://example.test/path",
    }

    async def fake_run_tool(cmd, **kwargs):
        commands.append(cmd)
        target_file = Path(cmd[cmd.index("-l") + 1])
        assert target_file.read_text().strip() == "https://example.test"
        assert "-no-interactsh" in cmd and "-disable-redirects" in cmd
        exclude = cmd[cmd.index("-exclude-tags") + 1]
        assert {"default-login", "oast", "dos", "bruteforce"}.issubset(set(exclude.split(",")))
        return ToolResult(cmd, 0, "", "", 0.01, json_data=[record, record])

    monkeypatch.setattr(nuclei, "run_tool", fake_run_tool)

    async def audit():
        ctx = ScanContext(
            target="example.test", base_url="https://example.test", case_dir=tmp_path,
            config={"nuclei_enabled": True, "request_headers": ["Authorization: Bearer secret"],
                    "rate_limit": 10, "nuclei_timeout": 60},
        )
        await nuclei.run(ctx, None)
        return ctx

    ctx = asyncio.run(audit())
    findings = [f for f in ctx.findings if f.module == "nuclei"]
    assert len(findings) == 1
    assert findings[0].type == "test-cve"
    assert findings[0].severity.name == "HIGH"
    assert findings[0].id
    assert "secret" not in findings[0].evidence
    assert commands


def test_nuclei_is_off_by_default(tmp_path: Path, monkeypatch):
    async def unexpected(*args, **kwargs):
        raise AssertionError("external binary must not run by default")
    monkeypatch.setattr(nuclei, "run_tool", unexpected)

    async def audit():
        ctx = ScanContext(target="example.test", base_url="https://example.test", case_dir=tmp_path)
        await nuclei.run(ctx, None)
        return ctx
    assert asyncio.run(audit()).findings == []
