"""Разведка: DNS-записи, SPF/DMARC, поиск сабдоменов через CT-логи."""
from __future__ import annotations

import asyncio
import socket
from typing import Iterable

import httpx

from ..core import Finding, ScanContext, Severity

try:
    import dns.asyncresolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

NAME = "recon"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False

DNS_RECORDS = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]


async def _dns_lookup(domain: str) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}
    if not DNS_OK:
        try:
            results["A"] = [socket.gethostbyname(domain)]
        except Exception:
            pass
        return results

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 4
    resolver.lifetime = 6

    async def one(rtype: str):
        try:
            ans = await resolver.resolve(domain, rtype)
            results[rtype] = [r.to_text() for r in ans]
        except Exception:
            pass

    await asyncio.gather(*(one(r) for r in DNS_RECORDS))
    return results


async def _crtsh_subdomains(client: httpx.AsyncClient, domain: str) -> set[str]:
    subs: set[str] = set()
    try:
        r = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=15,
        )
        if r.status_code == 200 and r.text.strip().startswith("["):
            for entry in r.json():
                for nv in str(entry.get("name_value", "")).split("\n"):
                    nv = nv.strip().lower().lstrip("*.")
                    if nv.endswith(domain) and nv != domain:
                        subs.add(nv)
    except Exception:
        pass
    return subs


async def _resolve_many(subs: Iterable[str]) -> dict[str, str]:
    loop = asyncio.get_event_loop()

    def _one(host: str):
        try:
            return host, socket.gethostbyname(host)
        except Exception:
            return host, ""

    tasks = [loop.run_in_executor(None, _one, s) for s in subs]
    res = await asyncio.gather(*tasks)
    return {h: ip for h, ip in res if ip}


RU_RECORDS = {
    "A":     "IPv4-адреса сервера",
    "AAAA":  "IPv6-адреса сервера",
    "MX":    "почтовые серверы",
    "NS":    "DNS-серверы домена",
    "TXT":   "текстовые записи (часто SPF, верификации)",
    "SOA":   "техническая запись о зоне",
    "CNAME": "псевдоним (указатель на другое имя)",
    "CAA":   "кому разрешено выпускать SSL-сертификаты",
}


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    dns_data = await _dns_lookup(ctx.target)
    if dns_data:
        for rtype, values in dns_data.items():
            ctx.add(Finding(
                module=NAME,
                title=f"DNS-записи {rtype} ({RU_RECORDS.get(rtype, '')})",
                description=", ".join(values)[:300],
                severity=Severity.INFO,
                raw={"records": values, "type": rtype},
            ))
        if dns_data.get("A"):
            ctx.ip = dns_data["A"][0]

        spf_dmarc_ok = {"spf": False, "dmarc": False}
        for t in dns_data.get("TXT", []):
            if "v=spf1" in t.lower():
                spf_dmarc_ok["spf"] = True
        if DNS_OK:
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 5
                ans = await resolver.resolve(f"_dmarc.{ctx.target}", "TXT")
                if any("v=DMARC1" in r.to_text() for r in ans):
                    spf_dmarc_ok["dmarc"] = True
            except Exception:
                pass

        if not spf_dmarc_ok["spf"]:
            ctx.add(Finding(
                module=NAME,
                title="Отсутствует SPF-запись",
                severity=Severity.LOW,
                description="В DNS нет TXT-записи v=spf1. Это значит, что от вашего домена "
                            "проще отправлять поддельные письма (фишинг от вашего имени).",
                remediation='Добавьте TXT-запись, например: "v=spf1 -all" если домен не отправляет почту, '
                            'или "v=spf1 include:_spf.google.com -all" если используете Google Workspace.',
                cwe="CWE-290",
            ))
        if not spf_dmarc_ok["dmarc"]:
            ctx.add(Finding(
                module=NAME,
                title="Отсутствует DMARC-запись",
                severity=Severity.LOW,
                description="Не настроен DMARC. Это политика, которая говорит почтовикам, "
                            "что делать с подделанными письмами от вашего домена.",
                remediation='Добавьте TXT-запись для _dmarc.<домен>: '
                            '"v=DMARC1; p=reject; rua=mailto:postmaster@<домен>"',
                cwe="CWE-290",
            ))

    # CT-логи: сабдомены
    subs = await _crtsh_subdomains(client, ctx.target)
    if subs:
        resolved = await _resolve_many(subs)
        sev = Severity.INFO if len(subs) < 25 else Severity.LOW
        ctx.add(Finding(
            module=NAME,
            title=f"Найдены сабдомены через журналы сертификатов: {len(subs)} шт. "
                  f"(из них рабочих: {len(resolved)})",
            severity=sev,
            description="Эти имена когда-то получали SSL-сертификат, "
                        "значит они известны злоумышленникам.\n\n" +
                        "\n".join(f"  • {s}" for s in sorted(subs)[:40]) +
                        (f"\n  ... ещё {len(subs)-40}" if len(subs) > 40 else ""),
            remediation="Проверьте, что все эти сабдомены действительно нужны. "
                        "Удалите DNS-записи для забытых/устаревших. "
                        "Закройте сабдомены с dev/staging/test от публичного доступа." if sev > Severity.INFO else None,
            raw={"all": sorted(subs), "resolved": resolved},
        ))
        ctx.config["subdomains"] = sorted(subs)
        ctx.config["resolved_subdomains"] = resolved
