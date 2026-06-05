"""Опциональное ARP-сканирование локальной сети. Требует scapy + root + разрешение."""
from __future__ import annotations

import asyncio
import ipaddress
import socket

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "local_arp"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False


def _local_subnet() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except Exception:
        return None


def _arp_scan(cidr: str):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                 timeout=2, verbose=False)
    return [(r.psrc, r.hwsrc) for _, r in ans]


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    if not ctx.permissions.get("local_arp"):
        return
    if not SCAPY_OK:
        ctx.add(Finding(module=NAME, title="ARP-скан отключён (не установлен scapy)",
                        severity=Severity.INFO))
        return
    cidr = ctx.config.get("local_cidr") or _local_subnet()
    if not cidr:
        ctx.add(Finding(module=NAME, title="Не удалось определить локальную подсеть",
                        severity=Severity.INFO))
        return
    loop = asyncio.get_event_loop()
    try:
        hosts = await loop.run_in_executor(None, _arp_scan, cidr)
    except PermissionError:
        ctx.add(Finding(module=NAME, title="Для ARP-скана нужен root / cap_net_raw",
                        severity=Severity.INFO))
        return
    except Exception as e:
        ctx.add(Finding(module=NAME, title="Ошибка ARP-скана",
                        description=str(e), severity=Severity.INFO))
        return
    for ip, mac in hosts:
        ctx.add(Finding(module=NAME, title=f"Устройство в локальной сети: {ip}",
                        description=f"MAC-адрес: {mac}", severity=Severity.INFO))
