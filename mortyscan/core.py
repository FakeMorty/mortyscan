"""Core data structures, severity, findings registry, async HTTP client."""
from __future__ import annotations

import asyncio
import dataclasses
import enum
import hashlib
import json
import logging
import random
import string
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx

LOG = logging.getLogger("mortyscan")

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 MortyScan/17.0"
)


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 10
    MEDIUM = 30
    HIGH = 60
    CRITICAL = 90

    @property
    def label(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return {
            "INFO": "cyan",
            "LOW": "blue",
            "MEDIUM": "yellow",
            "HIGH": "red",
            "CRITICAL": "bold red",
        }[self.name]


@dataclass
class Finding:
    """A single discovered fact or vulnerability."""
    module: str
    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    evidence: str = ""
    target: str = ""
    url: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    remediation: Optional[str] = None
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    category: Optional[str] = None
    confidence: Optional[str] = None
    source: Optional[str] = None
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    type: Optional[str] = None
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.type is None:
            self.type = self.module

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.label
        d["severity_score"] = int(self.severity)
        return d


@dataclass
class ScanContext:
    """Shared state between modules during a scan."""
    target: str                          # bare domain, e.g. example.com
    base_url: str                        # e.g. https://example.com
    ip: Optional[str] = None
    case_dir: Path = field(default_factory=lambda: Path("."))
    findings: list[Finding] = field(default_factory=list)
    crawled_urls: set[str] = field(default_factory=set)
    discovered_params: dict[str, set[str]] = field(default_factory=dict)
    discovered_forms: list[dict] = field(default_factory=list)
    tech: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    baseline_404: dict[str, Any] = field(default_factory=dict)
    permissions: dict[str, bool] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    site_info: dict[str, Any] = field(default_factory=dict)
    waf: list[dict[str, str]] = field(default_factory=list)
    script_urls: set[str] = field(default_factory=set)
    endpoints: set[str] = field(default_factory=set)
    seen_jwts: set[str] = field(default_factory=set, repr=False)
    sqli_candidates: list[dict[str, Any]] = field(default_factory=list, repr=False)
    xss_candidates: list[dict[str, Any]] = field(default_factory=list, repr=False)
    auth: dict[str, Any] = field(default_factory=dict, repr=False)

    def add(self, f: Finding) -> Finding:
        f.target = self.target
        self.findings.append(f)
        return f

    def risk_score(self) -> int:
        return sum(int(f.severity) for f in self.findings)

    def verdict(self) -> str:
        s = self.risk_score()
        if s >= 400:
            return "APOCALYPTIC"
        if s >= 200:
            return "CRITICAL"
        if s >= 100:
            return "HIGH"
        if s >= 40:
            return "MEDIUM"
        if s > 0:
            return "LOW"
        return "CLEAN"

    def verdict_ru(self) -> str:
        from .i18n import VERDICT_RU
        return VERDICT_RU.get(self.verdict(), self.verdict())


def host_in_scope(host: str, allowed_hosts: set[str]) -> bool:
    """Exact/domain-wildcard/CIDR allowlist match used by the request guard."""
    import ipaddress

    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for raw_entry in allowed_hosts:
        entry = str(raw_entry).strip().lower().rstrip(".")
        if not entry or entry.startswith("#"):
            continue
        wildcard = entry.startswith("*.")
        candidate = entry[2:] if wildcard else entry
        try:
            network = ipaddress.ip_network(candidate, strict=False)
            if address is not None and address in network:
                return True
            continue
        except ValueError:
            pass
        if host == candidate and not wildcard:
            return True
        if host.endswith("." + candidate):
            return True
    return False


def same_origin(url: str, origin: str) -> bool:
    """Return whether two absolute HTTP(S) URLs share scheme, host, and port."""
    try:
        left, right = httpx.URL(url), httpx.URL(origin)
        return (left.scheme in {"http", "https"}
                and (left.scheme, left.host.lower(), left.port)
                == (right.scheme, right.host.lower(), right.port))
    except Exception:
        return False


def make_client(
    timeout: float = 10.0,
    verify: bool = True,
    follow_redirects: bool = True,
    http2: bool = False,
    proxy: Optional[str] = None,
    ua: str = DEFAULT_UA,
    extra_headers: Optional[dict[str, str]] = None,
    auth_host: Optional[str] = None,
    auth_origin: Optional[str] = None,
    scope_hosts: Optional[set[str]] = None,
    rate_limit: float = 10.0,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> httpx.AsyncClient:
    limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
    if http2:
        try:
            import h2  # noqa: F401
        except ImportError:
            http2 = False
    request_headers = {
        "User-Agent": ua,
        "Accept": "*/*",
        "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.5",
    }
    safe_extra = {
        key: value for key, value in (extra_headers or {}).items()
        if key.lower() not in {"host", "content-length", "connection", "transfer-encoding", "proxy-authorization"}
    }
    request_headers.update(safe_extra)
    auth_names = [key for key in safe_extra]
    allowed = httpx.URL(auth_origin) if auth_origin else None
    allowed_host = (allowed.host if allowed else auth_host or "").lower().rstrip(".")
    allowed_scheme = allowed.scheme if allowed else None
    allowed_port = allowed.port if allowed else None
    scope = {str(item).strip().lower() for item in (scope_hosts or set()) if str(item).strip()}
    interval = 1.0 / max(0.1, float(rate_limit))
    rate_states: dict[str, tuple[asyncio.Lock, float]] = {}

    async def guard_request(request: httpx.Request) -> None:
        request_host = (request.url.host or "").lower().rstrip(".")
        if scope and not host_in_scope(request_host, scope):
            raise httpx.RequestError(f"Blocked out-of-scope request to {request_host}", request=request)
        if auth_origin or auth_host:
            same_host = request_host == allowed_host
            same_scheme = allowed_scheme is None or request.url.scheme == allowed_scheme
            same_port = allowed_port is None or request.url.port == allowed_port
            if not (same_host and same_scheme and same_port):
                # Login may add Authorization/Cookie after client construction, so
                # strip sensitive headers dynamically as well as configured headers.
                for header in set(auth_names) | {"authorization", "cookie", "proxy-authorization"}:
                    request.headers.pop(header, None)
        state = rate_states.get(request_host)
        if state is None:
            state = (asyncio.Lock(), 0.0)
            rate_states[request_host] = state
        lock = state[0]
        async with lock:
            previous = rate_states[request_host][1]
            delay = interval - (time.monotonic() - previous)
            if delay > 0:
                await asyncio.sleep(delay)
            rate_states[request_host] = (lock, time.monotonic())

    hooks = {"request": [guard_request]}
    return httpx.AsyncClient(
        timeout=timeout,
        verify=verify,
        follow_redirects=follow_redirects,
        http2=http2,
        limits=limits,
        headers=request_headers,
        event_hooks=hooks,
        proxy=proxy,
        transport=transport,
    )


def rand_str(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def page_signature(text: str) -> dict[str, Any]:
    """Cheap fingerprint of a response body for soft-404 detection."""
    text = text or ""
    return {
        "len": len(text),
        "sha": hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest(),
        "lines": text.count("\n"),
    }


def similarity(sig_a: dict, sig_b: dict, tol: float = 0.05) -> bool:
    """Return True if two signatures are 'about the same' page."""
    if sig_a.get("sha") == sig_b.get("sha"):
        return True
    la, lb = sig_a.get("len", 0), sig_b.get("len", 0)
    if la == 0 and lb == 0:
        return True
    biggest = max(la, lb, 1)
    return abs(la - lb) / biggest < tol


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
