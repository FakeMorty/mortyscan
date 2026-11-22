"""Tests for subprocess wrapper; all child processes are tiny local helpers."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.tools.runner import ToolNotFound, _safe_command, run_tool, start_tool_session


def test_runner_parses_jsonl_and_stdin():
    async def invoke():
        return await run_tool(
            [sys.executable, "-c", "import sys; print('{\"ok\":true}'); print(sys.stdin.read())"],
            timeout=3, capture_json=True, input_data="hello",
        )
    result = asyncio.run(invoke())
    assert result.returncode == 0
    assert result.json_data == [{"ok": True}]
    assert result.stdout.endswith("hello\n")


def test_runner_timeout_kills_child():
    async def invoke():
        return await run_tool([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.05)
    with pytest.raises(TimeoutError):
        asyncio.run(invoke())


def test_command_logging_redacts_auth_headers():
    safe = _safe_command(["tool", "-H", "Authorization: Bearer secret", "--cookie=session=abc",
                          "https://user:password@example.com/path?token=hidden"])
    assert "secret" not in safe and "session=abc" not in safe
    assert "password" not in safe and "hidden" not in safe and "user@" not in safe


def test_runner_missing_tool_is_graceful():
    async def invoke():
        return await run_tool(["mortyscan-definitely-not-a-real-binary"], timeout=1)
    with pytest.raises(ToolNotFound):
        asyncio.run(invoke())


def test_managed_tool_session_is_terminated_on_context_exit():
    async def invoke():
        async with await start_tool_session(
            [sys.executable, "-c", "import time; print('ready', flush=True); time.sleep(10)"], timeout=3
        ) as session:
            await asyncio.sleep(0.05)
            assert session.process.returncode is None
        return session.process.returncode
    assert asyncio.run(invoke()) is not None


def test_runner_timeout_also_kills_descendant_holding_pipes():
    child = "import time; time.sleep(10)"
    parent = "import subprocess,sys; subprocess.Popen([sys.executable, '-c', sys.argv[1]])"
    async def invoke():
        return await run_tool([sys.executable, "-c", parent, child], timeout=0.15)
    with pytest.raises(TimeoutError):
        asyncio.run(invoke())
