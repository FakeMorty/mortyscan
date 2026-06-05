"""Проверка возможного захвата сабдомена (subdomain takeover).
Использует список найденных модулем recon сабдоменов."""
from __future__ import annotations

import asyncio

import httpx

from ..core import Finding, ScanContext, Severity

try:
    import dns.asyncresolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

NAME = "takeover"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False

# Сигнатуры «осиротевших» сервисов на разных хостингах
FINGERPRINTS = [
    ("github.io",        "There isn't a GitHub Pages site here."),
    ("herokuapp.com",    "No such app"),
    ("herokudns.com",    "No such app"),
    ("amazonaws.com",    "NoSuchBucket"),
    ("s3.amazonaws.com", "The specified bucket does not exist"),
    ("cloudfront.net",   "Bad request"),
    ("azurewebsites.net","404 Web Site not found"),
    ("readthedocs.io",   "unknown to Read the Docs"),
    ("ghost.io",         "The thing you were looking for is no longer here"),
    ("surge.sh",         "project not found"),
    ("netlify.app",      "Not Found - Request ID"),
    ("netlify.com",      "Not Found - Request ID"),
    ("zendesk.com",      "Help Center Closed"),
    ("tumblr.com",       "There's nothing here."),
    ("wordpress.com",    "Do you want to register"),
    ("fastly.net",       "Fastly error: unknown domain"),
    ("pantheonsite.io",  "The gods are wise"),
    ("bitbucket.io",     "Repository not found"),
    ("statuspage.io",    "You are being"),
    ("uservoice.com",    "This UserVoice subdomain is currently available"),
    ("desk.com",         "Please try again or try Desk.com"),
    ("shopify.com",      "Sorry, this shop is currently unavailable"),
    ("teamwork.com",     "Oops - We didn't find your site"),
    ("helpjuice.com",    "We could not find what you're looking for"),
    ("helpscoutdocs.com","No settings were found for this company"),
    ("ghost.org",        "The thing you were looking for is no longer here"),
    ("acquia-sites.com", "The site you are looking for could not be found"),
]


async def _cname(host: str) -> str:
    if not DNS_OK:
        return ""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 4
        ans = await resolver.resolve(host, "CNAME")
        return str(ans[0].target).rstrip(".").lower()
    except Exception:
        return ""


async def _check(client: httpx.AsyncClient, host: str) -> tuple[str, str, str] | None:
    cname = await _cname(host)
    if not cname:
        return None
    for service, sign in FINGERPRINTS:
        if service in cname:
            for scheme in ("https", "http"):
                try:
                    r = await client.get(f"{scheme}://{host}", timeout=6)
                    body = (r.text or "")[:6000]
                    if sign.lower() in body.lower():
                        return host, cname, sign
                except Exception:
                    continue
    return None


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    subs = ctx.config.get("subdomains") or []
    if not subs:
        return
    sem = asyncio.Semaphore(20)

    async def guarded(h):
        async with sem:
            return await _check(client, h)

    results = await asyncio.gather(*[guarded(s) for s in subs], return_exceptions=True)
    found_any = False
    for r in results:
        if isinstance(r, tuple):
            host, cname, sign = r
            found_any = True
            ctx.add(Finding(
                module=NAME,
                title=f"Возможный захват сабдомена: {host}",
                severity=Severity.HIGH, cwe="CWE-350", cvss=8.1,
                url=f"https://{host}",
                evidence=f"CNAME → {cname}; маркер: «{sign}»",
                description=f"Сабдомен {host} указывает (CNAME) на {cname}, "
                            "но сам сервис там не зарегистрирован. Злоумышленник может "
                            "зарегистрировать его и разместить контент от имени вашего домена.",
                remediation="Удалите DNS-запись CNAME, либо заново зарегистрируйте сервис "
                            "(GitHub Pages, Heroku app и т.п.) под этот сабдомен.",
            ))
    if not found_any and subs:
        ctx.add(Finding(
            module=NAME,
            title=f"Проверены сабдомены на захват: уязвимых не найдено ({len(subs)} шт.)",
            severity=Severity.INFO,
        ))
