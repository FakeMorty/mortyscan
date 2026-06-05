"""Асинхронное сканирование TCP-портов и захват баннеров."""
from __future__ import annotations

import asyncio
import socket

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "ports"
REQUIRES_INTRUSIVE = False
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


async def _scan_port(host: str, port: int, sem: asyncio.Semaphore,
                     grab_timeout: float = 1.5) -> tuple[int, str] | None:
    async with sem:
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


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    host = ctx.ip or ctx.target
    try:
        socket.gethostbyname(host)
    except Exception:
        ctx.add(Finding(module=NAME, title="Не удалось определить IP для сканирования портов",
                        description=host, severity=Severity.INFO))
        return

    sem = asyncio.Semaphore(200)
    tasks = [_scan_port(host, p, sem) for p in TOP_PORTS]
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
