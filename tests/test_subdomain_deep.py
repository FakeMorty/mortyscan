"""DNS enumeration tests stub resolver results and never query real DNS."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import ScanContext
from mortyscan.modules import subdomain_deep


def test_subdomain_module_filters_wildcard_and_updates_takeover_inventory(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(subdomain_deep, "_load_words", lambda: ["api", "wild"])
    async def no_subfinder(root, timeout, env=None):
        return set()
    async def resolve(host, gate, semaphore):
        if host.startswith("mortyscan-"):
            return ["203.0.113.10"]
        if host == "api.example.com":
            return ["198.51.100.20"]
        if host == "wild.example.com":
            return ["203.0.113.10"]
        return []
    async def cname(host, gate):
        return "api-host.example-cdn.invalid" if host == "api.example.com" else ""
    monkeypatch.setattr(subdomain_deep, "_run_subfinder", no_subfinder)
    monkeypatch.setattr(subdomain_deep, "_resolve_ips", resolve)
    monkeypatch.setattr(subdomain_deep, "_cname", cname)

    async def audit():
        ctx = ScanContext(
            target="example.com", base_url="https://example.com", case_dir=tmp_path,
            config={"deep_subdomains": True, "no_external": True, "subdomain_max": 20, "rate_limit": 100},
            permissions={"intrusive": True},
        )
        await subdomain_deep.run(ctx, None)
        return ctx

    ctx = asyncio.run(audit())
    assert ctx.config["subdomains"] == ["api.example.com"]
    assert ctx.config["resolved_subdomains"]["api.example.com"] == ["198.51.100.20"]
    assert ctx.config["subdomain_cnames"]["api.example.com"] == "api-host.example-cdn.invalid"
    assert "wild.example.com" not in ctx.config["subdomains"]
    assert any("новых поддоменов 1" in finding.title for finding in ctx.findings)


def test_subdomain_module_skips_deep_bruteforce_without_explicit_flag(tmp_path: Path, monkeypatch):
    calls = []
    async def passive(root, timeout, env=None):
        calls.append((root, timeout))
        return set()
    monkeypatch.setattr(subdomain_deep, "_run_subfinder", passive)
    monkeypatch.setattr(subdomain_deep, "_resolve_ips", lambda *args: asyncio.sleep(0, result=[]))

    async def audit():
        ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                          config={"no_external": True})
        await subdomain_deep.run(ctx, None)
        return ctx
    ctx = asyncio.run(audit())
    assert calls == []  # no external discovery when requested
    assert not ctx.config.get("subdomains")


def test_subfinder_is_default_but_wordlist_bruteforce_is_opt_in(tmp_path: Path, monkeypatch):
    called = []
    async def passive(root, timeout, env=None):
        called.append((root, env))
        return {"api.example.com"}
    async def resolve(host, gate, semaphore):
        return ["198.51.100.55"] if host == "api.example.com" else []
    async def cname(host, gate):
        return ""
    def no_wordlist():
        raise AssertionError("default scan must not brute force the bundled list")
    monkeypatch.setattr(subdomain_deep, "_run_subfinder", passive)
    monkeypatch.setattr(subdomain_deep, "_resolve_ips", resolve)
    monkeypatch.setattr(subdomain_deep, "_cname", cname)
    monkeypatch.setattr(subdomain_deep, "_load_words", no_wordlist)

    async def audit():
        ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                          config={"subdomain_max": 5, "rate_limit": 100})
        await subdomain_deep.run(ctx, None)
        return ctx
    ctx = asyncio.run(audit())
    assert called == [("example.com", None)]
    assert ctx.config["subdomains"] == ["api.example.com"]


def test_deep_enumeration_requires_runtime_permission(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(subdomain_deep, "_load_words", lambda: (_ for _ in ()).throw(
        AssertionError("wordlist must not run without active authorization")))
    monkeypatch.setattr(subdomain_deep, "_resolve_ips", lambda *args: asyncio.sleep(0, result=[]))
    async def audit():
        ctx = ScanContext(target="example.com", base_url="https://example.com", case_dir=tmp_path,
                          config={"deep_subdomains": True, "no_external": True})
        await subdomain_deep.run(ctx, None)
        return ctx
    ctx = asyncio.run(audit())
    assert any("нет активного разрешения" in finding.title for finding in ctx.findings)
