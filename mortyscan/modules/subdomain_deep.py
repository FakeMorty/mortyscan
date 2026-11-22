"""DNS-брутифорс и пассивные источники для углублённой инвентаризации поддоменов."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from pathlib import Path

import httpx

from ..core import Finding, ScanContext, Severity, host_in_scope, rand_str
from ..tools.runner import ToolNotFound, run_tool
from .crawler import _registrable

NAME = "subdomain_deep"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False
LOG = logging.getLogger("mortyscan.subdomain_deep")
_MUTATION_PREFIXES = ("dev-", "test-", "staging-", "preprod-")
_MUTATION_SUFFIXES = ("-dev", "-test", "-staging", "-qa", "-01", "-02", "01", "02")


class _RateGate:
    def __init__(self, rate: float) -> None:
        self.interval = 1.0 / max(0.1, rate)
        self.lock = asyncio.Lock()
        self.last = 0.0

    async def wait(self) -> None:
        async with self.lock:
            delay = self.interval - (time.monotonic() - self.last)
            if delay > 0:
                await asyncio.sleep(delay)
            self.last = time.monotonic()


def _load_words() -> list[str]:
    path = Path(__file__).resolve().parents[1] / "data" / "subdomains.txt"
    return [line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def _allowed_name(host: str, root: str, ctx: ScanContext) -> bool:
    host = host.lower().rstrip(".")
    root = root.lower().rstrip(".")
    if host != root and not host.endswith("." + root):
        return False
    scope = set(ctx.config.get("scope_hosts", []))
    if scope:
        return host_in_scope(host, scope)
    return True


def _mutations(names: set[str], root: str) -> set[str]:
    results = set()
    for name in names:
        labels = name.lower().rstrip(".").split(".")
        if len(labels) < 2 or not name.endswith("." + root):
            continue
        left = labels[0]
        for prefix in _MUTATION_PREFIXES:
            results.add(f"{prefix}{left}.{root}")
        for suffix in _MUTATION_SUFFIXES:
            results.add(f"{left}{suffix}.{root}")
    return results


async def _resolve_ips(host: str, gate: _RateGate, semaphore: asyncio.Semaphore) -> list[str]:
    async with semaphore:
        await gate.wait()
        try:
            import dns.asyncresolver
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 4
            async def query(record_type: str):
                try:
                    answer = await resolver.resolve(host, record_type)
                    return [str(item) for item in answer]
                except Exception:
                    return []
            answers = await asyncio.gather(query("A"), query("AAAA"))
            ips = {str(ipaddress.ip_address(value)) for group in answers for value in group}
            return sorted(ips)
        except ImportError:
            pass
        except Exception:
            return []
        try:
            loop = asyncio.get_running_loop()
            records = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=4)
        except Exception:
            return []
    ips = set()
    for record in records:
        try:
            ips.add(str(ipaddress.ip_address(record[4][0])))
        except (ValueError, IndexError):
            continue
    return sorted(ips)


async def _cname(host: str, gate: _RateGate) -> str:
    try:
        import dns.asyncresolver
    except ImportError:
        return ""
    await gate.wait()
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3
        answer = await resolver.resolve(host, "CNAME")
        return str(answer[0].target).rstrip(".").lower()
    except Exception:
        return ""


def _proxy_env(ctx: ScanContext) -> dict[str, str] | None:
    proxy = str(ctx.config.get("proxy") or "")
    if not proxy:
        return None
    return {key: proxy for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")}


async def _run_subfinder(root: str, timeout: int, env: dict[str, str] | None = None) -> set[str]:
    result = await run_tool(["subfinder", "-d", root, "-silent", "-all", "-recursive"],
                            timeout=timeout, env=env)
    return set(sorted({line.strip().lower().rstrip(".") for line in result.stdout.splitlines()
                       if line.strip() and not line.startswith("[")})[:5000])


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    del client
    deep_requested = bool(ctx.config.get("deep_subdomains"))
    deep = deep_requested and bool(ctx.permissions.get("intrusive"))
    if deep_requested and not deep:
        ctx.add(Finding(module=NAME, title="Глубокая DNS-энумерация пропущена: нет активного разрешения",
                        severity=Severity.INFO, source="permission gate", confidence="high"))
    root = _registrable(ctx.target)
    known = set(str(host).lower().rstrip(".") for host in ctx.config.get("subdomains", []))
    resolved_known = ctx.config.get("resolved_subdomains", {}) or {}
    if isinstance(resolved_known, dict):
        known.update(str(host).lower().rstrip(".") for host in resolved_known)
    allowed_known = {host for host in known if _allowed_name(host, root, ctx)}

    subfinder_names: set[str] = set()
    amass_names: set[str] = set()
    tool_missing = False
    if ctx.config.get("scope_hosts"):
        # subprocess networking cannot be intercepted by the HTTP scope guard.
        ctx.add(Finding(
            module=NAME, title="Внешняя энумерация пропущена при активном --scope-file", severity=Severity.INFO,
            description="Subfinder/Amass могут запрашивать источники вне allowlist; используются только локальные кандидаты, фильтруемые по scope.",
            source="scope enforcement", confidence="high",
        ))
    elif ctx.config.get("no_external"):
        pass
    else:
        LOG.warning("Subfinder passive enumeration enabled for root=%s", root)
        try:
            subfinder_names = await _run_subfinder(root, max(1, min(300, int(ctx.config.get("subfinder_timeout", 120)))),
                                                   env=_proxy_env(ctx))
        except ToolNotFound:
            tool_missing = True
            LOG.warning("tool_missing: subfinder")
        except TimeoutError:
            ctx.add(Finding(module=NAME, title="Subfinder остановлен по таймауту",
                            severity=Severity.INFO, source="subprocess timeout", confidence="high"))
        except Exception as exc:
            LOG.warning("subfinder failed: %s", type(exc).__name__)
        if deep:
            try:
                LOG.warning("Amass passive enumeration enabled for root=%s", root)
                result = await run_tool(["amass", "enum", "-passive", "-d", root],
                                        timeout=max(1, min(600, int(ctx.config.get("amass_timeout", 300)))),
                                        env=_proxy_env(ctx))
                amass_names = set(sorted({line.strip().lower().rstrip(".") for line in result.stdout.splitlines()
                                           if line.strip() and not line.startswith("[")})[:5000])
            except ToolNotFound:
                LOG.warning("tool_missing: amass")
                ctx.add(Finding(module=NAME, title="Внешний инструмент не установлен: Amass",
                                severity=Severity.INFO, source="tool availability",
                                description="Продолжена DNS-энумерация без Amass."))
            except TimeoutError:
                ctx.add(Finding(module=NAME, title="Amass остановлен по таймауту",
                                severity=Severity.INFO, source="subprocess timeout"))
            except Exception as exc:
                LOG.warning("amass failed: %s", type(exc).__name__)

    word_candidates = _load_words() if deep else []
    if ctx.config.get("mutate") and deep:
        word_candidates.extend(sorted(_mutations(allowed_known | subfinder_names | amass_names, root)))
    max_candidates = max(1, min(5000, int(ctx.config.get("subdomain_max", 500))))
    brute_hosts: list[str] = []
    seen_brute: set[str] = set()
    for word in word_candidates:
        word = word.strip().lower().rstrip(".")
        # Wordlist entries may be labels or explicit FQDNs; never append arbitrary external names.
        candidate = word if "." in word else f"{word}.{root}"
        if (candidate not in seen_brute and candidate.endswith("." + root)
                and _allowed_name(candidate, root, ctx) and candidate not in allowed_known):
            brute_hosts.append(candidate)
            seen_brute.add(candidate)
        if len(brute_hosts) >= max_candidates:
            break
    passive_names = subfinder_names | amass_names
    host_candidates = set(brute_hosts)
    host_candidates.update(name for name in passive_names if _allowed_name(name, root, ctx) and name not in allowed_known)
    rate = float(ctx.config.get("rate_limit", 10.0))
    gate = _RateGate(rate)
    semaphore = asyncio.Semaphore(30)

    # Detect wildcard DNS and avoid reporting every random label as a real host.
    wildcard_signatures = set()
    if host_candidates:
        for _ in range(2):
            probe = f"mortyscan-{rand_str(14)}.{root}"
            if not _allowed_name(probe, root, ctx):
                break
            ips = await _resolve_ips(probe, gate, semaphore)
            if ips:
                wildcard_signatures.add(tuple(ips))

    async def resolve_candidate(host: str) -> tuple[str, list[str]] | None:
        ips = await _resolve_ips(host, gate, semaphore)
        if not ips or tuple(ips) in wildcard_signatures:
            return None
        return host, ips

    results = await asyncio.gather(*(resolve_candidate(host) for host in sorted(host_candidates)))
    resolved = ({host: value for host, value in resolved_known.items() if _allowed_name(str(host), root, ctx)}
                if isinstance(resolved_known, dict) else {})
    for name, value in list(resolved.items()):
        if value:
            resolved[name] = value if isinstance(value, list) else [value]
    discovered: dict[str, list[str]] = {}
    for item in results:
        if item:
            host, ips = item
            resolved[host] = ips
            discovered[host] = ips
    known_to_resolve = sorted(host for host in allowed_known | passive_names
                              if _allowed_name(host, root, ctx) and not resolved.get(host))[:2000]
    known_ips = await asyncio.gather(*(_resolve_ips(host, gate, semaphore) for host in known_to_resolve))
    for host, ips in zip(known_to_resolve, known_ips):
        if ips:
            resolved[host] = ips

    cnames = {}
    for host in list(discovered)[:100]:
        cname = await _cname(host, gate)
        if cname:
            cnames[host] = cname

    all_names = sorted(host for host in {*allowed_known, *passive_names, *discovered}
                       if _allowed_name(host, root, ctx))
    ctx.config["subdomains"] = all_names
    ctx.config["resolved_subdomains"] = resolved
    ctx.config["subdomain_cnames"] = cnames
    if discovered:
        ctx.add(Finding(
            module=NAME,
            title=f"Глубокая DNS-разведка: найдено новых поддоменов {len(discovered)}",
            severity=Severity.INFO,
            description="Собраны только имена и DNS-адреса. Доступность HTTP-служб этим модулем не проверялась.",
            evidence="; ".join(f"{host} → {', '.join(ips)}" for host, ips in list(sorted(discovered.items()))[:30]),
            source="DNS resolution", confidence="medium",
            tags=["subdomain", "dns-enumeration"],
            raw={"new_hosts": discovered, "cname": cnames, "wildcard_dns_filtered": bool(wildcard_signatures)},
        ))
    else:
        ctx.add(Finding(
            module=NAME,
            title="Глубокая DNS-разведка завершена: новых поддоменов не обнаружено",
            severity=Severity.INFO,
            description=f"Проверено candidate-имён: {len(host_candidates)}; CT/Subfinder-имён в scope: {len(allowed_known | subfinder_names)}.",
            raw={"candidates_checked": len(host_candidates), "wildcard_dns_filtered": bool(wildcard_signatures)},
        ))
    if tool_missing:
        ctx.add(Finding(
            module=NAME, title="Внешний инструмент не установлен: subfinder", severity=Severity.INFO,
            description="Пассивный сбор пропущен; встроенный DNS-брутифорс доступен только с --deep-subdomains. Для пассивных источников установите Subfinder или используйте recon/CT.",
            raw={"tool_missing": "subfinder"}, source="tool availability", confidence="high",
        ))
