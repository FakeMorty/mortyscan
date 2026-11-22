"""Консервативное пассивное распознавание WAF/CDN по ответу сайта."""
from __future__ import annotations

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "waf"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False

_TAMPER_CHAINS = {
    "cloudflare": ["between", "randomcase", "space2comment"],
    "modsecurity": ["space2comment", "percentage", "randomcase"],
    "akamai": ["charencode", "randomcase"],
    "f5": ["between", "charencode"],
}


def get_tamper_chain(waf_name: str) -> list[str]:
    """Return the documented SQLMap suggestion for a WAF fingerprint (not a bypass guarantee)."""
    normalized = str(waf_name or "").strip().lower()
    for signature, chain in _TAMPER_CHAINS.items():
        if signature in normalized:
            return list(chain)
    return ["space2comment"]


_SIGNATURES = (
    ("Cloudflare", ("cf-ray", "cf-cache-status", "cloudflare")),
    ("Akamai", ("akamai-ghost", "x-akamai-transformed", "akamai-")),
    ("Imperva/Incapsula", ("x-iinfo", "visid_incap_", "incap_ses_")),
    ("F5 BIG-IP", ("bigipserver", "f5-trafficshield", "x-wa-info")),
    ("AWS WAF", ("x-amzn-waf-action",)),
    ("Sucuri", ("x-sucuri-id", "sucuri/")),
    ("ModSecurity (возможный)", ("mod_security", "modsecurity")),
)


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    try:
        response = await client.get(ctx.base_url, follow_redirects=False)
    except Exception as exc:
        ctx.add(Finding(
            module=NAME, title="WAF не удалось определить", severity=Severity.INFO,
            description=f"Пассивный fingerprint пропущен: {type(exc).__name__}.",
            source="HTTP headers/body", confidence="low",
        ))
        return

    header_blob = "\n".join(f"{key}: {value}" for key, value in response.headers.items()).lower()
    cookie_blob = "\n".join(response.headers.get_list("set-cookie")).lower()
    sample = (response.text or "")[:32768].lower()
    haystack = "\n".join((header_blob, cookie_blob, sample))
    matches = []
    for name, signatures in _SIGNATURES:
        if any(signature in haystack for signature in signatures):
            matches.append({"name": name, "confidence": "high" if name in {"Cloudflare", "Akamai", "Imperva/Incapsula"} else "medium"})

    # Generic CDN hints are deliberately informational and are not labelled as a WAF.
    if not matches:
        generic = any(k in response.headers for k in ("via", "x-cache", "x-served-by", "x-cdn"))
        ctx.waf = []
        ctx.add(Finding(
            module=NAME,
            title="WAF не обнаружен" if not generic else "Обнаружен возможный CDN/edge proxy",
            severity=Severity.INFO,
            description=("По типовым признакам WAF не найден; это не доказывает его отсутствие." if not generic
                         else "Есть признаки промежуточного CDN/прокси, но их недостаточно, чтобы уверенно назвать его WAF."),
            evidence=", ".join(k for k in ("via", "x-cache", "x-served-by", "x-cdn") if k in response.headers),
            source="HTTP response fingerprint", confidence="low",
        ))
        return

    ctx.waf = matches
    ctx.add(Finding(
        module=NAME,
        title="Возможный защитный edge/WAF: " + ", ".join(item["name"] for item in matches),
        severity=Severity.INFO,
        description="Fingerprint основан на публичных заголовках, cookie и тексте ответа; "
                    "он не доказывает, что правила WAF включены или блокируют конкретные атаки.",
        evidence="; ".join(f"{item['name']} ({item['confidence']})" for item in matches),
        source="HTTP response fingerprint", confidence="high" if any(x["confidence"] == "high" for x in matches) else "medium",
        tags=["waf", "fingerprint"],
    ))
