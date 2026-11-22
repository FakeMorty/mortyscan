"""Explicit, low-volume Interactsh OOB probes for in-scope GET parameters and headers."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlparse, urlunsplit

import httpx

from ..core import Finding, ScanContext, Severity, host_in_scope
from ..tools.runner import ToolNotFound, start_tool_session
from .crawler import _registrable

NAME = "oast"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False
MAX_PROBES = 12
MAX_INTERACTION_LOG_BYTES = 2 * 1024 * 1024
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
LOG = logging.getLogger("mortyscan.oast")


def _in_scope(ctx: ScanContext, url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        hosts = set(ctx.config.get("scope_hosts", []))
        return host_in_scope(parsed.hostname, hosts) if hosts else _registrable(parsed.hostname) == _registrable(ctx.target)
    except Exception:
        return False


def _server_name(value: str) -> str:
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else "//" + value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("interactsh server must not contain credentials, query, or fragment")
    host = (parsed.hostname or "").strip(".")
    if not host or not HOST_RE.fullmatch(host):
        raise ValueError("invalid interactsh server name")
    return host


def _candidate_probes(ctx: ScanContext, max_probes: int = MAX_PROBES) -> list[dict]:
    probes = []
    seen = set()
    parameter_limit = max(0, max_probes - 2)
    for path, names in ctx.discovered_params.items():
        base_candidates = [url for url in ctx.crawled_urls if urlparse(url).path == path]
        if not base_candidates:
            base_candidates = [urljoin(ctx.base_url.rstrip("/") + "/", path.lstrip("/"))]
        for url in base_candidates:
            parsed = urlparse(url)
            clean_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
            if not _in_scope(ctx, clean_url):
                continue
            original = dict(parse_qsl(parsed.query, keep_blank_values=True))
            for name in sorted(names):
                if not name or len(name) > 100:
                    continue
                key = (clean_url, str(name), "parameter")
                if key in seen:
                    continue
                seen.add(key)
                probes.append({"kind": "parameter", "url": clean_url, "name": str(name), "params": dict(original)})
                if len(probes) >= parameter_limit:
                    break
            if len(probes) >= parameter_limit:
                break
        if len(probes) >= parameter_limit:
            break
    for kind in ("X-Forwarded-Host", "Host"):
        url = ctx.base_url
        if _in_scope(ctx, url) and len(probes) < max_probes:
            probes.append({"kind": kind, "url": url, "name": "", "params": {}})
    return probes[:max_probes]


def _candidate_write_probes(ctx: ScanContext) -> list[dict]:
    """Only use discovered POST forms; caller requires a separate interactive confirmation."""
    probes = []
    webhook_names = {"webhook", "webhook_url", "callback", "callback_url", "notify_url", "hook_url"}
    for form in ctx.discovered_forms:
        if str(form.get("method", "GET")).upper() != "POST":
            continue
        url = str(form.get("url", ""))
        if not _in_scope(ctx, url):
            continue
        names = [str(item.get("name", "")) for item in form.get("inputs", []) if isinstance(item, dict)]
        webhook_name = next((name for name in names if name.lower() in webhook_names), None)
        if webhook_name and len(probes) < 2:
            probes.append({"kind": "webhook-json", "url": url, "name": webhook_name})
            continue
        if len(probes) < 2:
            probes.append({"kind": "xml-xxe", "url": url, "name": "xml"})
        if len(probes) >= 2:
            break
    return probes[:2]


def _payload_hosts(path: Path, count: int) -> list[str]:
    try:
        if not path.is_file() or path.stat().st_size > 64 * 1024:
            return []
        lines = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
                 if line.strip()]
    except OSError:
        return []
    return [value for value in lines if HOST_RE.fullmatch(value) and "." in value][:count]


def _interaction_kind(text: str) -> str:
    try:
        item = json.loads(text)
        if isinstance(item, dict):
            for key in ("protocol", "type", "interaction_type"):
                if item.get(key):
                    return re.sub(r"[^A-Za-z0-9_-]", "", str(item[key]))[:40] or "interaction"
    except (ValueError, TypeError):
        pass
    lowered = text.lower()
    for term in ("http", "dns", "smtp", "ldap"):
        if term in lowered:
            return term
    return "oob"


def _read_hits(path: Path, mapping: dict[str, dict]) -> dict[str, str]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_INTERACTION_LOG_BYTES:
            return {}
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    hits = {}
    for line in lines:
        lowered = line.lower()
        for correlation, probe in mapping.items():
            if correlation in lowered and correlation not in hits:
                hits[correlation] = _interaction_kind(line)
    return hits


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    if not ctx.config.get("oast_enabled"):
        return
    if not ctx.permissions.get("intrusive"):
        ctx.add(Finding(module=NAME, title="OAST пропущен: требуется активное разрешение",
                        severity=Severity.INFO, source="permission gate", confidence="high"))
        return
    if ctx.config.get("no_external"):
        ctx.add(Finding(module=NAME, title="OAST пропущен (--no-external)", severity=Severity.INFO,
                        source="operator option", confidence="high"))
        return
    write_enabled = bool(ctx.config.get("oast_write_probes") and ctx.config.get("oast_write_confirmed"))
    if ctx.config.get("oast_write_probes") and not ctx.config.get("oast_write_confirmed"):
        ctx.add(Finding(module=NAME, title="OAST POST probes пропущены: нет отдельного TTY-подтверждения",
                        severity=Severity.INFO, source="safety gate", confidence="high"))
    probes = _candidate_probes(ctx, MAX_PROBES - 2 if write_enabled else MAX_PROBES)
    if write_enabled:
        probes.extend(_candidate_write_probes(ctx))
    if not probes:
        ctx.add(Finding(module=NAME, title="OAST пропущен: нет безопасных in-scope кандидатов",
                        severity=Severity.INFO, description="Не обнаружены in-scope GET-параметры/endpoint'ы или подтверждённые POST forms для OAST probes.",
                        source="candidate gate", confidence="high"))
        return
    try:
        server = _server_name(str(ctx.config.get("interactsh_url") or ""))
    except ValueError as exc:
        ctx.add(Finding(module=NAME, title="OAST server configuration is invalid", severity=Severity.INFO,
                        description=str(exc), source="configuration gate", confidence="high"))
        return

    LOG.warning("OAST explicitly enabled: registering at %s and sending up to %s probes to target=%s write_probes=%s",
                server or "default Interactsh servers", len(probes), ctx.target, write_enabled)
    with tempfile.TemporaryDirectory(prefix="mortyscan-oast-") as work:
        payload_file = Path(work) / "payloads.txt"
        interactions_file = Path(work) / "interactions.jsonl"
        command = ["interactsh-client", "-n", str(len(probes)), "-pi", "5", "-json", "-duc",
                   "-psf", str(payload_file), "-o", str(interactions_file)]
        if server:
            command.extend(["-server", server])
        env = {}
        proxy = str(ctx.config.get("proxy") or "")
        if proxy:
            env.update({"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "ALL_PROXY": proxy,
                        "http_proxy": proxy, "https_proxy": proxy, "all_proxy": proxy})
        try:
            session = await start_tool_session(command, timeout=120, env=env or None)
        except ToolNotFound:
            ctx.add(Finding(module=NAME, title="interactsh-client не установлен — OAST пропущен",
                            severity=Severity.INFO, description="Установите ProjectDiscovery interactsh-client и повторите явный запуск с --oast.",
                            source="tool availability", confidence="high"))
            return
        except Exception as exc:
            ctx.add(Finding(module=NAME, title="Не удалось запустить Interactsh client", severity=Severity.INFO,
                            description=f"Запуск отклонён ({type(exc).__name__}).", source="subprocess wrapper", confidence="high"))
            return

        async with session:
            deadline = time.monotonic() + 20
            payloads = []
            while time.monotonic() < deadline and not payloads and session.returncode is None:
                payloads = _payload_hosts(payload_file, len(probes))
                if not payloads:
                    await asyncio.sleep(0.25)
            if len(payloads) < len(probes):
                ctx.add(Finding(module=NAME, title="Interactsh payloads не готовы вовремя", severity=Severity.INFO,
                                description=f"Получено payloads={len(payloads)} из {len(probes)}; запросы к цели не отправлялись.",
                                source="OAST registration", confidence="high"))
                return
            mapping = {}
            payload_probe = {}
            for payload, probe in zip(payloads, probes):
                correlation = payload.split(".", 1)[0].lower()
                payload_probe[payload] = (correlation, probe)
            requests_sent = 0
            rate = max(1.0, float(ctx.config.get("rate_limit", 10.0)))
            send_deadline = time.monotonic() + min(30.0, 5.0 + len(payload_probe) / rate)
            for payload, (correlation, probe) in payload_probe.items():
                if time.monotonic() >= send_deadline:
                    break
                if not _in_scope(ctx, probe["url"]):
                    continue
                try:
                    if probe["kind"] == "parameter":
                        params = dict(probe["params"])
                        params[probe["name"]] = payload
                        request = client.get(probe["url"], params=params, follow_redirects=False)
                    elif probe["kind"] in {"X-Forwarded-Host", "Host"}:
                        headers = {probe["kind"]: payload}
                        request = client.get(probe["url"], headers=headers, follow_redirects=False)
                    elif probe["kind"] == "webhook-json":
                        request = client.post(probe["url"], json={probe["name"]: f"https://{payload}"},
                                              follow_redirects=False)
                    elif probe["kind"] == "xml-xxe":
                        document = (f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY morty SYSTEM "http://{payload}/">]>'
                                    '<root>&morty;</root>')
                        request = client.post(probe["url"], content=document,
                                              headers={"Content-Type": "application/xml"}, follow_redirects=False)
                    else:
                        continue
                    remaining = send_deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    await asyncio.wait_for(request, timeout=min(5.0, remaining))
                    requests_sent += 1
                    mapping[correlation] = probe
                except Exception:
                    continue
            poll_seconds = 60 if requests_sent else 0
            poll_deadline = time.monotonic() + poll_seconds
            hits = {}
            while time.monotonic() < poll_deadline and len(hits) < len(mapping):
                hits.update(_read_hits(interactions_file, mapping))
                if len(hits) < len(mapping):
                    await asyncio.sleep(min(5.0, max(0.0, poll_deadline - time.monotonic())))
            for correlation, interaction in hits.items():
                probe = mapping[correlation]
                target_parsed = urlparse(probe["url"])
                target_url = urlunsplit((target_parsed.scheme, target_parsed.netloc, target_parsed.path, "", ""))
                kind = probe["kind"]
                is_xxe = kind == "xml-xxe"
                ctx.add(Finding(module=NAME,
                                title=("Подтверждён blind XXE/OAST callback" if is_xxe
                                       else "Подтверждённый blind SSRF/OAST callback"),
                                severity=Severity.HIGH, cwe="CWE-611" if is_xxe else "CWE-918", cvss=8.0,
                                url=target_url,
                                evidence=f"interaction={interaction}; probe={kind}; корреляция подтверждена",
                                description=("После явно разрешённой XML POST-пробы Interactsh получил внешний callback. Это подтверждает OOB XXE-взаимодействие, но не доказывает чтение локальных файлов или RCE."
                                             if is_xxe else "После Interactsh probe получен внешний callback. Это подтверждает OOB-взаимодействие, но не доказывает RCE или чтение чувствительных данных."),
                                remediation="Ограничьте исходящие соединения сервера; отключите обработку внешних XML entities, валидируйте URL allowlist и не доверяйте forwarded headers.",
                                source="Interactsh OOB", confidence="confirmed",
                                tags=["oast", "xxe" if is_xxe else "ssrf", "confirmed"],
                                raw={"interaction": interaction, "probe_kind": kind,
                                     "parameter": probe.get("name") or None,
                                     "correlation_hash": hashlib.sha256(correlation.encode()).hexdigest()}))
            ctx.add(Finding(module=NAME, title=f"OAST завершён: probes {requests_sent}, callbacks {len(hits)}",
                            severity=Severity.INFO,
                            description=("Отправлялись read-only GET-запросы по in-scope URLs; POST не выполнялся."
                                         if not write_enabled else "Отправлялись in-scope GET и до двух явно подтверждённых XML/webhook POST probes; серверное изменение состояния возможно."),
                            source="Interactsh", confidence="high",
                            raw={"probes": requests_sent, "callbacks": len(hits), "poll_seconds": poll_seconds,
                                 "server": server or "default", "post_probes": write_enabled,
                                 "application_state_change_possible": write_enabled, "rce_probes": False}))
