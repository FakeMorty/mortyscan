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
    ts: float = field(default_factory=time.time)

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

    def add(self, f: Finding) -> Finding:
        f.target = self.target
        self.findings.append(f)
        return f

    def risk_score(self) -> int:
        return sum(int(f.severity) for f in self.findings)

    def verdict(self) -> str:
        s = self.risk_score()
        if s >= 400: return "APOCALYPTIC"
        if s >= 200: return "CRITICAL"
        if s >= 100: return "HIGH"
        if s >= 40: return "MEDIUM"
        if s > 0:   return "LOW"
        return "CLEAN"

    def verdict_ru(self) -> str:
        from .i18n import VERDICT_RU
        return VERDICT_RU.get(self.verdict(), self.verdict())


def make_client(
    timeout: float = 10.0,
    verify: bool = True,
    follow_redirects: bool = True,
    http2: bool = False,
    proxy: Optional[str] = None,
    ua: str = DEFAULT_UA,
) -> httpx.AsyncClient:
    limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
    # http2=True требует пакета h2; включаем только если он установлен
    if http2:
        try:
            import h2  # noqa: F401
        except ImportError:
            http2 = False
    return httpx.AsyncClient(
        timeout=timeout,
        verify=verify,
        follow_redirects=follow_redirects,
        http2=http2,
        limits=limits,
        headers={"User-Agent": ua, "Accept": "*/*", "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.5"},
        proxy=proxy,
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
