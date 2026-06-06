"""Пассивные сведения о сайте: HTTP-профиль, IP/ASN/страна, RDAP/регистратор, CDN/WAF."""
from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from ..core import ScanContext

NAME = "siteinfo"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_reserved)
    except ValueError:
        return False


def _safe_text(v: object) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ", ".join(_safe_text(x) for x in v if x is not None)
    return str(v)


def _detect_edge(headers: httpx.Headers) -> dict[str, str]:
    h = {k.lower(): v for k, v in headers.items()}
    server = h.get("server", "")
    x_powered = h.get("x-powered-by", "")
    result: dict[str, str] = {}

    if "cf-ray" in h or "cloudflare" in server.lower():
        result["cdn_waf"] = "Cloudflare"
    elif "x-amz-cf-id" in h or "cloudfront" in server.lower():
        result["cdn_waf"] = "Amazon CloudFront"
    elif "x-served-by" in h and "fastly" in h.get("via", "").lower():
        result["cdn_waf"] = "Fastly"
    elif "akamai" in h.get("via", "").lower() or "x-akamai" in h:
        result["cdn_waf"] = "Akamai"
    elif "x-sucuri-id" in h or "x-sucuri-cache" in h:
        result["cdn_waf"] = "Sucuri"
    elif "x-cdn" in h:
        result["cdn_waf"] = h.get("x-cdn", "")

    if result.get("cdn_waf"):
        result["note"] = (
            "Похоже, сайт находится за CDN/WAF. Геолокация IP может относиться к edge-узлу, "
            "а не к origin-серверу."
        )
    if x_powered and "cdn_waf" not in result:
        result["note"] = f"Приложение раскрывает X-Powered-By: {x_powered}"
    return result


async def _http_profile(client: httpx.AsyncClient, base_url: str) -> dict:
    info: dict = {}
    try:
        r = await client.get(base_url)
    except Exception:
        return info

    text = r.text or ""
    soup = None
    title = ""
    html_lang = ""
    if "text/html" in (r.headers.get("content-type", "").lower()) and text:
        try:
            soup = BeautifulSoup(text[:500_000], "lxml")
        except Exception:
            soup = None
    if soup:
        if soup.title and soup.title.string:
            title = soup.title.string.strip()[:200]
        if soup.html and soup.html.get("lang"):
            html_lang = soup.html.get("lang", "")[:50]

    redirects = []
    for h in r.history:
        redirects.append({
            "status": h.status_code,
            "url": str(h.url),
            "location": h.headers.get("location", ""),
        })

    info.update({
        "status_code": r.status_code,
        "final_url": str(r.url),
        "http_version": getattr(r, "http_version", "") or "HTTP/1.1",
        "redirects": redirects,
        "content_type": r.headers.get("content-type", ""),
        "content_length": r.headers.get("content-length", ""),
        "server": r.headers.get("server", ""),
        "x_powered_by": r.headers.get("x-powered-by", ""),
        "title": title,
        "lang": html_lang,
    })
    info.update(_detect_edge(r.headers))
    return info


async def _geoip(client: httpx.AsyncClient, ip: str) -> dict:
    if not _is_public_ip(ip):
        return {}
    endpoints = [
        f"https://ipwho.is/{ip}",
        f"https://ipapi.co/{ip}/json/",
    ]
    for url in endpoints:
        try:
            r = await client.get(url, timeout=12)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            data = r.json()
        except Exception:
            continue

        if "ipwho.is" in url and data.get("success") is False:
            continue

        if "ipwho.is" in url:
            conn = data.get("connection", {}) or {}
            tz = data.get("timezone", {}) or {}
            return {
                "country": data.get("country", ""),
                "country_code": data.get("country_code", ""),
                "region": data.get("region", ""),
                "city": data.get("city", ""),
                "timezone": tz.get("id", "") or data.get("timezone", ""),
                "asn": conn.get("asn", ""),
                "org": conn.get("org", ""),
            }

        return {
            "country": data.get("country_name", "") or data.get("country", ""),
            "country_code": data.get("country_code", ""),
            "region": data.get("region", ""),
            "city": data.get("city", ""),
            "timezone": data.get("timezone", ""),
            "asn": data.get("asn", ""),
            "org": data.get("org", ""),
        }
    return {}


def _extract_registrar(obj: dict) -> str:
    registrar = obj.get("registrarName") or obj.get("registrar") or ""
    if registrar:
        return str(registrar)
    for ent in obj.get("entities", []) or []:
        roles = {r.lower() for r in ent.get("roles", [])}
        if "registrar" not in roles:
            continue
        vcard = ent.get("vcardArray", [])
        if len(vcard) == 2:
            for item in vcard[1]:
                if item and item[0] == "fn" and len(item) >= 4:
                    return str(item[3])
    return ""


async def _rdap_domain(client: httpx.AsyncClient, host: str) -> dict:
    if not host or _is_ip(host) or host in {"localhost"}:
        return {}
    try:
        r = await client.get(f"https://rdap.org/domain/{host}", timeout=15)
    except Exception:
        return {}
    if r.status_code != 200:
        return {}
    try:
        data = r.json()
    except Exception:
        return {}

    reg_date = ""
    exp_date = ""
    for event in data.get("events", []) or []:
        action = (event.get("eventAction") or "").lower()
        date = event.get("eventDate", "")
        if action in {"registration", "registered"} and not reg_date:
            reg_date = date
        if action in {"expiration", "expired"} and not exp_date:
            exp_date = date

    return {
        "registrar": _extract_registrar(data),
        "registered": reg_date,
        "expires": exp_date,
        "statuses": data.get("status", []) or [],
        "dnssec": data.get("secureDNS", {}).get("delegationSigned"),
    }


def _ptr_lookup(ip: str | None) -> str:
    if not ip:
        return ""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _fmt_dt(value: str) -> str:
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.strftime("%d.%m.%Y %H:%M UTC")
    except Exception:
        return value


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    host = urlparse(ctx.base_url).hostname or ctx.target
    info: dict = {
        "network": {},
        "domain": {},
        "http": {},
        "edge": {},
    }

    info["network"]["ip"] = ctx.ip or ""
    info["network"]["ptr"] = _ptr_lookup(ctx.ip)

    try:
        v6 = socket.getaddrinfo(host, None, socket.AF_INET6)
        if v6:
            info["network"]["ipv6"] = v6[0][4][0]
    except Exception:
        pass

    http_info = await _http_profile(client, ctx.base_url)
    if http_info:
        info["http"].update({
            "status_code": http_info.get("status_code", ""),
            "final_url": http_info.get("final_url", ""),
            "http_version": http_info.get("http_version", ""),
            "redirect_chain": [
                f"{x.get('status', '')} {x.get('url', '')}"
                + (f" → {x.get('location', '')}" if x.get("location") else "")
                for x in http_info.get("redirects", [])
            ],
            "content_type": http_info.get("content_type", ""),
            "content_length": http_info.get("content_length", ""),
            "title": http_info.get("title", ""),
            "lang": http_info.get("lang", ""),
            "server": http_info.get("server", ""),
            "x_powered_by": http_info.get("x_powered_by", ""),
        })
        if http_info.get("cdn_waf"):
            info["edge"]["cdn_waf"] = http_info.get("cdn_waf", "")
        if http_info.get("note"):
            info["edge"]["note"] = http_info.get("note", "")

    if _is_public_ip(ctx.ip):
        geo = await _geoip(client, ctx.ip or "")
        if geo:
            info["network"].update(geo)
    else:
        info["network"]["note"] = "Локальный/частный адрес — внешнее гео/ASN-обогащение пропущено."

    rdap = await _rdap_domain(client, host)
    if rdap:
        rdap["registered"] = _fmt_dt(rdap.get("registered", ""))
        rdap["expires"] = _fmt_dt(rdap.get("expires", ""))
        info["domain"].update(rdap)

    cleaned: dict[str, dict] = {}
    for section, payload in info.items():
        if not isinstance(payload, dict):
            continue
        section_clean = {}
        for k, v in payload.items():
            if isinstance(v, list):
                if v:
                    section_clean[k] = [str(x) for x in v if str(x).strip()]
            elif isinstance(v, bool) or str(v).strip():
                section_clean[k] = v
        if section_clean:
            cleaned[section] = section_clean

    if cleaned:
        ctx.site_info.update(cleaned)
