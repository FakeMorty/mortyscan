"""Асинхронное сканирование TCP-портов и захват баннеров."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import socket
import time
import xml.etree.ElementTree as ET

import httpx

from ..core import Finding, ScanContext, Severity, host_in_scope
from ..tools.runner import ToolNotFound, run_tool

NAME = "ports"
LOG = logging.getLogger("mortyscan.ports")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False

TOP_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 631: "ipp", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker (без TLS)", 2376: "docker-tls", 2379: "etcd",
    3000: "node/grafana", 3306: "mysql", 3389: "rdp",
    4444: "metasploit", 5000: "upnp/node", 5432: "postgres",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 7001: "weblogic", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8086: "influxdb", 8088: "hadoop", 8161: "activemq",
    8443: "https-alt", 8888: "http-alt", 9000: "sonarqube",
    9042: "cassandra", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongodb", 27018: "mongodb",
    50070: "hadoop", 61616: "activemq",
}

# Опасные сервисы, которые часто оставляют без пароля
DANGEROUS_OPEN = {
    6379: ("Redis", "Часто без пароля — мгновенный слив всех данных и захват сервера."),
    11211: ("Memcached", "Без аутентификации по умолчанию. Может использоваться для усиления DDoS."),
    27017: ("MongoDB", "По умолчанию без пароля. Слив всей базы за минуты."),
    9200:  ("Elasticsearch", "По умолчанию без пароля. Часто содержит логи с персональными данными."),
    2375:  ("Docker API", "Открытый Docker без TLS = полный root на сервере."),
    2379:  ("etcd", "База конфигурации Kubernetes. Слив = захват всего кластера."),
    5984:  ("CouchDB", "Часто незащищён."),
    9092:  ("Kafka", "Часто без auth. Чтение всех сообщений."),
}


class _RateGate:
    def __init__(self, rate: float) -> None:
        self.interval = 1 / max(0.1, rate)
        self.lock = asyncio.Lock()
        self.last = 0.0

    async def wait(self) -> None:
        async with self.lock:
            delay = self.interval - (time.monotonic() - self.last)
            if delay > 0:
                await asyncio.sleep(delay)
            self.last = time.monotonic()


async def _scan_port(host: str, port: int, sem: asyncio.Semaphore, gate: _RateGate,
                     grab_timeout: float = 1.5) -> tuple[int, str] | None:
    async with sem:
        await gate.wait()
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=1.2)
        except (asyncio.TimeoutError, OSError):
            return None
        banner = ""
        try:
            if port in (80, 8080, 8000, 8888, 8081, 8008):
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=grab_timeout)
            banner = data.decode("utf-8", errors="ignore").strip().replace("\r", " ")[:160]
        except Exception:
            pass
        finally:
            try: writer.close(); await writer.wait_closed()
            except Exception: pass
        return port, banner


def _parse_nmap_xml(ctx: ScanContext, xml_text: str) -> int:
    if len(xml_text) > 5 * 1024 * 1024:
        raise ValueError("Nmap XML exceeds 5 MiB safety limit")
    root = ET.fromstring(xml_text)
    emitted = 0
    expected_host = (ctx.ip or ctx.target).lower().rstrip(".")
    for host in root.findall("host")[:8]:
        address = next((item.get("addr") for item in host.findall("address")
                        if item.get("addrtype") in {"ipv4", "ipv6"}), expected_host)
        if str(address).lower().rstrip(".") != expected_host:
            LOG.warning("Ignoring Nmap XML host outside requested target: %s", address)
            continue
        for port_node in host.findall("./ports/port")[:256]:
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                port = int(port_node.get("portid", "0"))
            except ValueError:
                continue
            service = port_node.find("service")
            service_parts = []
            if service is not None:
                service_parts = [str(service.get(key, ""))[:100] for key in ("name", "product", "version", "tunnel") if service.get(key)]
            service_desc = " ".join(service_parts) or "unknown service"
            ctx.add(Finding(module=NAME, title=f"Nmap: open {port}/{service_desc[:120]}", severity=Severity.LOW,
                            description="Порт открыт. Версия получена через ограниченный Nmap -sV; подтвердите необходимость внешнего доступа.",
                            source="Nmap XML", confidence="medium",
                            raw={"address": str(address), "port": port, "protocol": port_node.get("protocol", "tcp"),
                                 "service": service_desc}))
            emitted += 1
            for script in port_node.findall("script")[:50]:
                script_id = str(script.get("id", "nse-script"))[:120]
                output = str(script.get("output", ""))[:16000]
                cves = sorted({match.upper() for match in CVE_RE.findall(output)})[:20]
                vulnerable = bool(re.search(r"\bVULNERABLE\b", output, re.I))
                severity = Severity.HIGH if vulnerable else Severity.MEDIUM if cves else Severity.INFO
                summary_hash = hashlib.sha256(output.encode("utf-8", errors="replace")).hexdigest()
                ctx.add(Finding(module=NAME, title=f"Nmap NSE: {script_id} on {port}", severity=severity,
                                description=("NSE скрипт сообщил о потенциальной уязвимости; проверьте результат вручную."
                                             if vulnerable or cves else "NSE скрипт вернул дополнительную информацию."),
                                evidence=f"output_sha256={summary_hash}; cves={','.join(cves) or 'none'}",
                                source="Nmap NSE", confidence="medium" if vulnerable or cves else "low",
                                references=[f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in cves[:5]],
                                tags=["nmap", "nse", *(["cve"] if cves else [])],
                                raw={"script_id": script_id, "port": port, "cves": cves,
                                     "vulnerable_marker": vulnerable, "output_sha256": summary_hash}))
                emitted += 1
    return emitted


async def _run_nmap(ctx: ScanContext, host: str) -> None:
    if not ctx.config.get("nmap_enabled"):
        return
    if not ctx.permissions.get("intrusive"):
        ctx.add(Finding(module=NAME, title="Nmap пропущен: требуется активное разрешение", severity=Severity.INFO,
                        source="permission gate", confidence="high"))
        return
    if ctx.config.get("no_external"):
        ctx.add(Finding(module=NAME, title="Nmap пропущен (--no-external)", severity=Severity.INFO,
                        source="operator option", confidence="high"))
        return
    if ctx.config.get("proxy"):
        ctx.add(Finding(module=NAME, title="Nmap пропущен: raw TCP скан не может использовать настроенный HTTP proxy",
                        severity=Severity.INFO, source="proxy safety gate", confidence="high"))
        return
    scope_hosts = set(ctx.config.get("scope_hosts", []))
    if scope_hosts and not host_in_scope(ctx.target, scope_hosts):
        ctx.add(Finding(module=NAME, title="Nmap пропущен: цель вне scope",
                        severity=Severity.INFO, source="scope enforcement", confidence="high"))
        return
    timeout = max(10, min(900, int(ctx.config.get("nmap_timeout", 300))))
    # Bounded connect scan of common ports; the more invasive NSE families are explicit via --nmap.
    cmd = ["nmap", "-sT", "-sV", "-sC", "--script", "vuln,ssl-enum-ciphers,http-enum",
           "-oX", "-", "-n", "-Pn", "-T3", "--top-ports", "100",
           "--scan-delay", f"{max(1, int(1000 / max(0.1, float(ctx.config.get('rate_limit', 10.0)))))}ms",
           "--host-timeout", f"{timeout}s", "--max-retries", "1", host]
    LOG.warning("Nmap scan explicitly enabled for target=%s; ports/scripts may cause external requests", host)
    try:
        result = await run_tool(cmd, timeout=timeout, capture_json=False)
    except ToolNotFound:
        LOG.warning("tool_missing: nmap")
        ctx.add(Finding(module=NAME, title="Nmap не установлен — глубокое сканирование портов пропущено",
                        severity=Severity.INFO, source="tool availability", confidence="high"))
        return
    except TimeoutError:
        ctx.add(Finding(module=NAME, title="Nmap остановлен по таймауту", severity=Severity.INFO,
                        description=f"Процесс завершён после {timeout} секунд.", source="subprocess timeout", confidence="high"))
        return
    if result.returncode != 0 and not result.stdout.strip():
        ctx.add(Finding(module=NAME, title=f"Nmap завершился с кодом {result.returncode}", severity=Severity.INFO,
                        description="XML не получен; stderr не сохраняется в отчёт.", source="Nmap", confidence="high"))
        return
    try:
        emitted = _parse_nmap_xml(ctx, result.stdout)
    except (ET.ParseError, ValueError) as exc:
        ctx.add(Finding(module=NAME, title="Не удалось разобрать Nmap XML", severity=Severity.INFO,
                        description=f"Результат пропущен ({type(exc).__name__}).", source="Nmap XML", confidence="high"))
        return
    ctx.add(Finding(module=NAME, title=f"Nmap завершён: findings {emitted}", severity=Severity.INFO,
                    source="Nmap XML", confidence="high",
                    raw={"returncode": result.returncode, "stdout_truncated": result.stdout_truncated,
                         "ports_scanned": 100}))


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    host = ctx.ip or ctx.target
    try:
        socket.gethostbyname(host)
    except Exception:
        ctx.add(Finding(module=NAME, title="Не удалось определить IP для сканирования портов",
                        description=host, severity=Severity.INFO))
        return

    sem = asyncio.Semaphore(200)
    gate = _RateGate(float(ctx.config.get("rate_limit", 10.0)))
    tasks = [_scan_port(host, p, sem, gate) for p in TOP_PORTS]
    open_ports: list[tuple[int, str]] = []
    for coro in asyncio.as_completed(tasks):
        res = await coro
        if res:
            open_ports.append(res)

    for port, banner in sorted(open_ports):
        svc = TOP_PORTS.get(port, "?")
        if port in DANGEROUS_OPEN:
            name, why = DANGEROUS_OPEN[port]
            sev = Severity.HIGH
            title = f"Открыт ОПАСНЫЙ порт {port}/{name}"
            desc = f"{why}\nБаннер сервиса: {banner or '(пусто)'}"
            fix = ("Если сервис должен быть доступен только локально — привяжите его к 127.0.0.1 "
                   "или закройте файрволом. Если нужен наружу — обязательно установите аутентификацию.")
        else:
            sev = Severity.LOW
            title = f"Открыт порт {port}/{svc}"
            desc = f"Баннер сервиса: {banner or '(пусто)'}"
            fix = None
        ctx.add(Finding(module=NAME, title=title, severity=sev,
                        description=desc, evidence=banner, remediation=fix))

    if not open_ports:
        ctx.add(Finding(module=NAME, title="Открытых портов из топ-60 не обнаружено",
                        severity=Severity.INFO,
                        description="Все проверенные порты закрыты или отфильтрованы. Это хорошо."))
    await _run_nmap(ctx, host)
