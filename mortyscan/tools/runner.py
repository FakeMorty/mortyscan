"""Безопасный async wrapper для запуска внешних бинарников без shell."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import signal
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

LOG = logging.getLogger("mortyscan.tools")
_MAX_CAPTURE = 5 * 1024 * 1024


class ToolNotFound(FileNotFoundError):
    """Запрошенная внешняя программа не установлена."""


@dataclass
class ToolResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    json_data: Any = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class ToolSession:
    """Managed async subprocess lifetime for tools that must run while probes are sent."""
    def __init__(self, process: asyncio.subprocess.Process, command: list[str], timeout: float,
                 stdout_task: asyncio.Task, stderr_task: asyncio.Task, started: float) -> None:
        self.process = process
        self.command = list(command)
        self.timeout = timeout
        self.stdout_task = stdout_task
        self.stderr_task = stderr_task
        self.started = started
        self._closed = False
        self._watchdog = asyncio.create_task(self._enforce_deadline())

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    async def _enforce_deadline(self) -> None:
        try:
            await asyncio.sleep(self.timeout)
            if self.process.returncode is None:
                LOG.warning("tool session timeout after %.1fs: %s", self.timeout, _safe_command(self.command))
                await self._terminate(kill=True)
        except asyncio.CancelledError:
            return

    def _signal_group(self, sig: int) -> None:
        try:
            if os.name == "nt":
                if sig == signal.SIGKILL:
                    self.process.kill()
                elif self.process.returncode is None:
                    self.process.terminate()
            else:
                # The process group may outlive its leader; always address the saved pgid.
                os.killpg(self.process.pid, sig)
        except (ProcessLookupError, OSError):
            if self.process.returncode is None:
                try:
                    self.process.kill()
                except ProcessLookupError:
                    pass

    async def _terminate(self, *, kill: bool) -> None:
        self._signal_group(signal.SIGKILL if kill else signal.SIGTERM)
        try:
            await asyncio.wait_for(self.process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            self._signal_group(signal.SIGKILL)
            await self.process.wait()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if not self._watchdog.done():
            self._watchdog.cancel()
        await self._terminate(kill=False)
        drains = asyncio.gather(self.stdout_task, self.stderr_task, return_exceptions=True)
        try:
            output = await asyncio.wait_for(drains, timeout=2.0)
        except asyncio.TimeoutError:
            self._signal_group(signal.SIGKILL)
            output = await asyncio.gather(self.stdout_task, self.stderr_task, return_exceptions=True)
        if not self._watchdog.done():
            await asyncio.gather(self._watchdog, return_exceptions=True)
        sizes = [item[2] for item in output if isinstance(item, tuple) and len(item) == 3]
        LOG.info("tool session=%s rc=%s duration=%.2fs stdout=%d stderr=%d",
                 _safe_command(self.command), self.process.returncode,
                 time.monotonic() - self.started, sizes[0] if sizes else 0,
                 sizes[1] if len(sizes) > 1 else 0)

    @property
    def returncode(self) -> int | None:
        return self.process.returncode


def _safe_command(cmd: list[str]) -> str:
    """Не писать секреты из -H/--header в лог."""
    safe = list(cmd)
    redact_next = False
    for index, arg in enumerate(safe):
        if redact_next:
            safe[index] = "<redacted>"
            redact_next = False
        elif arg in {"-H", "--header", "--headers", "--cookie", "--cookies", "--proxy"}:
            redact_next = True
        elif arg.lower().startswith(("authorization:", "cookie:")):
            safe[index] = arg.split(":", 1)[0] + ": <redacted>"
        elif arg.lower().startswith(("--header=", "--headers=", "--cookie=", "--cookies=", "--proxy=")):
            safe[index] = arg.split("=", 1)[0] + "=<redacted>"
        elif arg.startswith(("http://", "https://")):
            try:
                parts = urlsplit(arg)
                if parts.query or parts.fragment or parts.username or parts.password:
                    host = parts.hostname or ""
                    if ":" in host and not host.startswith("["):
                        host = f"[{host}]"
                    try:
                        port = f":{parts.port}" if parts.port else ""
                    except ValueError:
                        port = ""
                    safe[index] = urlunsplit((parts.scheme, host + port, parts.path,
                                              "<query-redacted>" if parts.query else "", ""))
            except Exception:
                pass
        elif arg.lower().startswith("-h") and ":" in arg[2:]:
            safe[index] = "-H <redacted>"
    return " ".join(safe)


async def _read_bounded(stream: asyncio.StreamReader) -> tuple[bytes, bool, int]:
    chunks: list[bytes] = []
    stored = 0
    total = 0
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        total += len(chunk)
        room = _MAX_CAPTURE - stored
        if room > 0:
            piece = chunk[:room]
            chunks.append(piece)
            stored += len(piece)
    return b"".join(chunks), total > stored, total


def _parse_json(stdout: str) -> Any:
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        records = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records


async def run_tool(
    cmd: list[str], *, timeout: float, capture_json: bool = False,
    env: dict[str, str] | None = None, input_data: str | None = None,
) -> ToolResult:
    """Запустить программу без shell; дренировать оба pipe, ограничить память и убить group при timeout."""
    if not cmd or not cmd[0]:
        raise ValueError("cmd must contain an executable")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    executable = shutil.which(cmd[0])
    if executable is None:
        raise ToolNotFound(cmd[0])

    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    kwargs: dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(__import__("subprocess"), "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True

    safe_cmd = _safe_command(cmd)
    started = time.monotonic()
    process = await asyncio.create_subprocess_exec(
        executable, *cmd[1:],
        stdin=asyncio.subprocess.PIPE if input_data is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=run_env,
        **kwargs,
    )
    assert process.stdout and process.stderr
    stdout_task = asyncio.create_task(_read_bounded(process.stdout))
    stderr_task = asyncio.create_task(_read_bounded(process.stderr))
    async def feed_stdin() -> None:
        if input_data is None or process.stdin is None:
            return
        try:
            process.stdin.write(input_data.encode("utf-8"))
            await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            process.stdin.close()

    input_task = asyncio.create_task(feed_stdin())
    try:
        await asyncio.wait_for(asyncio.gather(process.wait(), input_task), timeout=timeout)
    except asyncio.TimeoutError:
        LOG.warning("tool timeout after %.1fs: %s", timeout, safe_cmd)
        try:
            if os.name == "nt":
                control_break = getattr(signal, "CTRL_BREAK_EVENT", None)
                if control_break is not None:
                    os.kill(process.pid, control_break)
                    try:
                        await asyncio.wait_for(process.wait(), timeout=0.25)
                    except asyncio.TimeoutError:
                        process.kill()
                else:
                    process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            if process.returncode is None:
                process.kill()
        await process.wait()
        await asyncio.gather(input_task, stdout_task, stderr_task, return_exceptions=True)
        raise TimeoutError(f"external tool timed out after {timeout:g}s: {cmd[0]}")

    try:
        remaining = max(0.001, timeout - (time.monotonic() - started))
        out, err = await asyncio.wait_for(asyncio.gather(stdout_task, stderr_task), timeout=remaining)
    except asyncio.TimeoutError:
        LOG.warning("tool descendants kept pipes open after %.1fs: %s", timeout, safe_cmd)
        try:
            if os.name == "nt":
                if process.returncode is None:
                    process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            if process.returncode is None:
                process.kill()
        await process.wait()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        raise TimeoutError(f"external tool timed out after {timeout:g}s: {cmd[0]}")
    stdout = out[0].decode("utf-8", errors="replace")
    stderr = err[0].decode("utf-8", errors="replace")
    duration = time.monotonic() - started
    LOG.info("tool=%s rc=%s duration=%.2fs stdout=%d stderr=%d", safe_cmd,
             process.returncode, duration, out[2], err[2])
    return ToolResult(
        command=list(cmd), returncode=int(process.returncode or 0),
        stdout=stdout, stderr=stderr, duration=duration,
        json_data=_parse_json(stdout) if capture_json else None,
        stdout_truncated=out[1], stderr_truncated=err[1],
    )


async def start_tool_session(cmd: list[str], *, timeout: float,
                            env: dict[str, str] | None = None) -> ToolSession:
    """Start a long-lived child under the same process-group and bounded-output policy as run_tool.

    Callers must use `async with` so the child is always terminated and joined, including on errors.
    """
    if not cmd or not cmd[0]:
        raise ValueError("cmd must contain an executable")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    executable = shutil.which(cmd[0])
    if executable is None:
        raise ToolNotFound(cmd[0])
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    kwargs: dict[str, Any] = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(__import__("subprocess"), "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    process = await asyncio.create_subprocess_exec(
        executable, *cmd[1:], stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=run_env, **kwargs,
    )
    assert process.stdout and process.stderr
    stdout_task = asyncio.create_task(_read_bounded(process.stdout))
    stderr_task = asyncio.create_task(_read_bounded(process.stderr))
    return ToolSession(process, cmd, timeout, stdout_task, stderr_task, time.monotonic())
