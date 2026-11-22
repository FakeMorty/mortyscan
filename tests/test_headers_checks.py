"""Регрессионные тесты дополнительных пассивных проверок HTTP-заголовков."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext
from mortyscan.modules import headers


def test_csp_parser_flags_weak_directives_and_respects_nonce():
    weak = headers._csp_issues(
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; base-uri 'self'"
    )
    assert any("unsafe-eval" in issue for issue in weak)
    assert any("unsafe-inline" in issue for issue in weak)
    assert any("object-src" in issue for issue in weak)

    nonce_policy = "script-src 'self' 'unsafe-inline' 'nonce-r4nd0m'; object-src 'none'; base-uri 'self'"
    assert headers._csp_issues(nonce_policy) == []


def test_header_audit_detects_weak_csp_hsts_and_cookie_flags(tmp_path: Path):
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "script-src 'self' 'unsafe-eval'; base-uri 'self'",
                "Strict-Transport-Security": "max-age=60",
                "Set-Cookie": "session=notsecure-value; SameSite=None",
            },
            request=request,
        )

    async def audit() -> list[str]:
        ctx = ScanContext(target="example.test", base_url="https://example.test", case_dir=tmp_path)
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            await headers.run(ctx, client)
        return [finding.title for finding in ctx.findings]

    titles = asyncio.run(audit())
    assert "Ослабленная политика Content-Security-Policy" in titles
    assert "Слабая настройка HSTS" in titles
    assert "Небезопасные cookie" in titles
