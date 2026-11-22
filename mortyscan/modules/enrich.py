"""Opt-in CVE enrichment with bounded public API lookups and a 24-hour cache."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

from ..core import Finding, ScanContext, Severity, host_in_scope
from .crawler import _registrable

NAME = "enrich"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False
LOG = logging.getLogger("mortyscan.enrich")
CACHE_TTL = 24 * 60 * 60
MAX_CACHE_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CVES = 100
MAX_DEPENDENCIES = 40
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_MANIFEST_NAMES = {
    "package.json", "package-lock.json", "composer.lock", "requirements.txt",
    "pipfile.lock", "yarn.lock", "pnpm-lock.yaml",
}


def _cache_dir(ctx: ScanContext) -> Path:
    configured = ctx.config.get("enrich_cache_dir")
    return Path(configured).expanduser() if configured else Path.home() / ".cache" / "mortyscan" / "enrich"


def _cached_json(path: Path):
    try:
        if path.stat().st_size > MAX_CACHE_BYTES or time.time() - path.stat().st_mtime > CACHE_TTL:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None


def _save_json(path: Path, data) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        LOG.debug("enrichment cache write failed (%s)", type(exc).__name__)


def _cve_ids(findings: list[Finding]) -> list[str]:
    found: set[str] = set()
    for finding in findings:
        for text in (finding.title, finding.description, finding.evidence):
            found.update(match.upper() for match in CVE_RE.findall(text or ""))
        raw_cves = finding.raw.get("cves", []) if isinstance(finding.raw, dict) else []
        if isinstance(raw_cves, list):
            for record in raw_cves:
                if isinstance(record, dict):
                    value = str(record.get("id") or record.get("cve") or "")
                    if CVE_RE.fullmatch(value):
                        found.add(value.upper())
    return sorted(found)[:MAX_CVES]


def _in_scope(ctx: ScanContext, url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        scope = set(ctx.config.get("scope_hosts", []))
        return host_in_scope(parsed.hostname, scope) if scope else _registrable(parsed.hostname) == _registrable(ctx.target)
    except Exception:
        return False


async def _response_json(client: httpx.AsyncClient, method: str, url: str, *, params=None, json_body=None):
    try:
        async with client.stream(method, url, params=params, json=json_body, timeout=8.0,
                                 follow_redirects=False) as response:
            if response.status_code != 200:
                return None
            chunks, size = [], 0
            async for chunk in response.aiter_bytes():
                piece = chunk[:MAX_CACHE_BYTES - size]
                chunks.append(piece)
                size += len(piece)
                if size >= MAX_CACHE_BYTES:
                    return None
            data = json.loads(b"".join(chunks).decode("utf-8", errors="strict"))
            return data if isinstance(data, (dict, list)) else None
    except Exception as exc:
        LOG.debug("enrichment API request failed (%s)", type(exc).__name__)
        return None


async def _epss(client: httpx.AsyncClient, cache: Path, cves: list[str]) -> dict[str, dict[str, float]]:
    output = {}
    pending = []
    for cve in cves:
        cached = _cached_json(cache / f"epss-{cve}.json")
        if isinstance(cached, dict):
            output[cve] = cached
        else:
            pending.append(cve)
    for start in range(0, len(pending), 100):
        batch = pending[start:start + 100]
        data = await _response_json(client, "GET", "https://api.first.org/data/v1/epss",
                                    params={"cve": ",".join(batch)})
        records = data.get("data", []) if isinstance(data, dict) else []
        for item in records if isinstance(records, list) else []:
            if not isinstance(item, dict):
                continue
            cve = str(item.get("cve", "")).upper()
            try:
                score = float(item["epss"])
                percentile = float(item["percentile"])
            except (KeyError, TypeError, ValueError):
                continue
            if cve in batch:
                value = {"epss": score, "percentile": percentile}
                output[cve] = value
                _save_json(cache / f"epss-{cve}.json", value)
    return output


async def _kev(client: httpx.AsyncClient, cache: Path) -> set[str]:
    path = cache / "cisa-kev.json"
    data = _cached_json(path)
    if not isinstance(data, dict):
        data = await _response_json(client, "GET", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        if isinstance(data, dict):
            _save_json(path, data)
    records = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    return {str(item.get("cveID", "")).upper() for item in records
            if isinstance(item, dict) and CVE_RE.fullmatch(str(item.get("cveID", "")))}


def _exact_version(value: object) -> str:
    version = str(value or "").strip()
    version = version.lstrip("^~>=< ")
    return version if re.fullmatch(r"v?\d+(?:\.\d+){0,3}(?:[-+][A-Za-z0-9.-]+)?", version) else ""


def _dependencies_from_manifest(name: str, text: str) -> list[tuple[str, str, str]]:
    dependencies = []
    try:
        data = json.loads(text) if name.endswith(".json") or name == "composer.lock" else None
    except (ValueError, TypeError):
        data = None
    if name == "package.json" and isinstance(data, dict):
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            values = data.get(section, {})
            if isinstance(values, dict):
                dependencies.extend(("npm", str(pkg), _exact_version(ver)) for pkg, ver in values.items())
    elif name == "package-lock.json" and isinstance(data, dict):
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for path, meta in packages.items():
                pkg = str(path).split("node_modules/")[-1]
                if pkg and pkg != path and isinstance(meta, dict):
                    dependencies.append(("npm", pkg, _exact_version(meta.get("version"))))
    elif name == "composer.lock" and isinstance(data, dict):
        for section in ("packages", "packages-dev"):
            for item in data.get(section, []) if isinstance(data.get(section), list) else []:
                if isinstance(item, dict):
                    dependencies.append(("Packagist", str(item.get("name", "")), _exact_version(item.get("version"))))
    elif name == "requirements.txt":
        for line in text.splitlines():
            match = re.match(r"\s*([A-Za-z0-9_.-]+)\s*==\s*([^;\s#]+)", line)
            if match:
                dependencies.append(("PyPI", match.group(1), _exact_version(match.group(2))))
    return list(dict.fromkeys(item for item in dependencies if item[1] and item[2]))[:MAX_DEPENDENCIES]


async def _manifest_dependencies(ctx: ScanContext, client: httpx.AsyncClient) -> list[tuple[str, str, str]]:
    found_urls = []
    for finding in ctx.findings:
        url = str(finding.url or "")
        if url and Path(urlparse(url).path).name.lower() in _MANIFEST_NAMES and _in_scope(ctx, url):
            found_urls.append(url)
    dependencies = []
    for url in list(dict.fromkeys(found_urls))[:8]:
        try:
            async with client.stream("GET", url, follow_redirects=False) as response:
                if response.status_code != 200:
                    continue
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    part = chunk[:MAX_MANIFEST_BYTES - size]
                    chunks.append(part)
                    size += len(part)
                    if size >= MAX_MANIFEST_BYTES:
                        break
                text = b"".join(chunks).decode("utf-8", errors="replace")
            dependencies.extend(_dependencies_from_manifest(Path(urlparse(url).path).name.lower(), text))
        except Exception:
            continue
    return list(dict.fromkeys(dependencies))[:MAX_DEPENDENCIES]


async def _osv(client: httpx.AsyncClient, cache: Path, dependencies: list[tuple[str, str, str]]) -> dict[str, list[dict]]:
    output = {}
    for ecosystem, name, version in dependencies:
        key = f"{ecosystem}:{name}@{version}"
        cache_file = cache / f"osv-{hashlib.sha256(key.encode()).hexdigest()}.json"
        data = _cached_json(cache_file)
        if not isinstance(data, dict):
            await asyncio.sleep(0.25)
            data = await _response_json(client, "POST", "https://api.osv.dev/v1/query",
                                        json_body={"package": {"ecosystem": ecosystem, "name": name}, "version": version})
            if isinstance(data, dict):
                _save_json(cache_file, data)
        vulns = data.get("vulns", []) if isinstance(data, dict) else []
        records = [item for item in vulns if isinstance(item, dict) and CVE_RE.search(json.dumps(item))]
        if records:
            output[key] = [{"id": str(item.get("id", "")),
                            "cves": sorted({match.upper() for match in CVE_RE.findall(json.dumps(item))})[:10],
                            "summary": str(item.get("summary", ""))[:300]} for item in records[:20]]
    return output


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    if not ctx.config.get("enrich_enabled"):
        return
    if ctx.config.get("no_external"):
        ctx.add(Finding(module=NAME, title="Enrichment пропущен (--no-external)", severity=Severity.INFO,
                        source="operator option", confidence="high"))
        return
    cves = _cve_ids(ctx.findings)
    LOG.warning("CVSS enrichment explicitly enabled: public CVE/package coordinates may be sent to EPSS/KEV/OSV providers (target=%s)", ctx.target)
    cache = _cache_dir(ctx)
    # Use a fresh unauthenticated client: only public CVE identifiers and package coordinates
    # leave the scanner, never target URLs, cookies, custom headers, or response bodies.
    transport = ctx.config.get("_enrich_test_transport")
    proxy = ctx.config.get("proxy") or None
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, proxy=proxy,
                                     transport=transport) as external:
            epss = await _epss(external, cache, cves)
            kev = await _kev(external, cache)
            dependencies = await _manifest_dependencies(ctx, client)
            osv = await _osv(external, cache, dependencies)
            osv_cves = sorted({cve for records in osv.values() for record in records
                               for cve in record.get("cves", [])})
            missing_cves = [cve for cve in osv_cves if cve not in cves]
            if missing_cves:
                epss.update(await _epss(external, cache, missing_cves[:MAX_CVES - len(cves)]))
            cves = sorted(set(cves) | set(osv_cves))[:MAX_CVES]
    except Exception as exc:
        LOG.warning("enrichment partially unavailable (%s)", type(exc).__name__)
        epss, kev, osv = {}, set(), {}

    attached = 0
    for finding in ctx.findings:
        matching = set()
        matching.update(match.upper() for match in CVE_RE.findall(" ".join((finding.title, finding.description, finding.evidence))))
        raw_cves = finding.raw.get("cves", []) if isinstance(finding.raw, dict) else []
        for record in raw_cves if isinstance(raw_cves, list) else []:
            if isinstance(record, dict):
                value = str(record.get("id") or record.get("cve") or "")
                if CVE_RE.fullmatch(value):
                    matching.add(value.upper())
        if not matching:
            continue
        top = sorted(matching)
        finding.raw = dict(finding.raw or {})
        finding.raw["enrichment"] = {
            "cves": {cve: {**epss.get(cve, {}), "in_kev": cve in kev} for cve in top},
            "epss": max((epss.get(cve, {}).get("epss", 0.0) for cve in top), default=0.0),
            "in_kev": any(cve in kev for cve in top),
        }
        attached += 1
    for package, records in osv.items():
        cve_list = sorted({cve for record in records for cve in record.get("cves", [])})
        if not cve_list:
            continue
        ctx.add(Finding(module=NAME, title=f"OSV: уязвимые зависимости {package}",
                        severity=Severity.MEDIUM,
                        description="Публичная база OSV сопоставила найденную версию зависимости с известными уязвимостями. Применимость проверьте по advisory и фактическому использованию пакета.",
                        evidence=", ".join(cve_list[:20]), references=[f"https://osv.dev/vulnerability/{record['id']}"
                            for record in records if record.get("id")][:10],
                        source="OSV query", confidence="medium",
                        raw={"package": package, "vulnerabilities": records,
                             "enrichment": {"cves": {cve: {**epss.get(cve, {}), "in_kev": cve in kev}
                                                       for cve in cve_list},
                                            "epss": max((epss.get(cve, {}).get("epss", 0.0) for cve in cve_list), default=0.0),
                                            "in_kev": any(cve in kev for cve in cve_list)}}))
    ctx.add(Finding(module=NAME, title=f"CVE enrichment: CVE {len(cves)}, EPSS {len(epss)}, KEV {len(kev)}, OSV {sum(map(len, osv.values()))}",
                    severity=Severity.INFO,
                    description="Обогащены только идентификаторы CVE и координаты зависимостей. Запросы к публичным базам не содержали URL цели, credentials или тел ответов.",
                    source="EPSS, CISA KEV, OSV", confidence="high",
                    raw={"cve_count": len(cves), "epss_count": len(epss), "kev_count": len(kev),
                         "osv_packages": len(osv), "findings_enriched": attached, "cache_ttl_seconds": CACHE_TTL}))
