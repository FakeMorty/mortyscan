"""Определение технологий + поиск известных уязвимостей (CVE) через NVD."""
from __future__ import annotations

import re

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "tech"
REQUIRES_INTRUSIVE = False
REQUIRES_STRESS = False

RULES = [
    ("WordPress", None, re.compile(r"/wp-content/|<meta name=\"generator\" content=\"WordPress ([\d.]+)", re.I)),
    ("Drupal",    None, re.compile(r"Drupal\.settings|X-Drupal-Cache", re.I)),
    ("Joomla",    None, re.compile(r"/media/jui/|Joomla!", re.I)),
    ("Bitrix",    None, re.compile(r"/bitrix/|BX\\.message", re.I)),
    ("Laravel",   re.compile(r"laravel_session", re.I), None),
    ("Django",    re.compile(r"csrftoken|sessionid", re.I), None),
    ("Flask",     re.compile(r"werkzeug", re.I), None),
    ("Express",   re.compile(r"express", re.I), None),
    ("Next.js",   None, re.compile(r"/_next/static/", re.I)),
    ("React",     None, re.compile(r"react(-dom)?@?[\d.]*\.js|data-reactroot", re.I)),
    ("Vue",       None, re.compile(r"vue(\.runtime)?\.(min\.)?js", re.I)),
    ("Angular",   None, re.compile(r"ng-version=", re.I)),
    ("jQuery",    None, re.compile(r"jquery[.-]?([\d.]+)?(\.min)?\.js", re.I)),
    ("nginx",     re.compile(r"^nginx", re.I), None),
    ("Apache",    re.compile(r"^Apache", re.I), None),
    ("IIS",       re.compile(r"Microsoft-IIS", re.I), None),
    ("PHP",       re.compile(r"php/", re.I), None),
    ("OpenResty", re.compile(r"openresty", re.I), None),
    ("Tomcat",    re.compile(r"tomcat", re.I), None),
]


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    try:
        r = await client.get(ctx.base_url)
    except Exception:
        return
    body = r.text or ""
    server = r.headers.get("server", "")
    powered = r.headers.get("x-powered-by", "")
    cookies = "; ".join(f"{c.name}={c.value}" for c in r.cookies)

    detected: dict[str, str] = {}

    for label, hre, bre in RULES:
        ver = ""
        hit = False
        if hre and (hre.search(server) or hre.search(powered) or hre.search(cookies)):
            hit = True
            # Берём версию ТОЛЬКО из источника, где сматчилось имя технологии,
            # чтобы не приписать PHP версию из «Server: Werkzeug/3.1.8».
            for hay in (server, powered, cookies):
                if hre.search(hay):
                    m = re.search(r"([\d]+\.[\d]+(?:\.[\d]+)?)", hay)
                    if m: ver = m.group(1); break
        if bre:
            m = bre.search(body)
            if m:
                hit = True
                if m.groups():
                    for g in m.groups():
                        if g and re.match(r"^\d", g):
                            ver = g; break
        if hit:
            detected[label] = ver

    for label, ver in detected.items():
        title = f"Технология обнаружена: {label}" + (f" {ver}" if ver else "")
        ctx.tech[label] = ver
        ctx.add(Finding(
            module=NAME, title=title, severity=Severity.INFO,
            description=f"Распознано по заголовкам/телу ответа/cookie. "
                        f"server={server or '—'}, X-Powered-By={powered or '—'}",
        ))

        if ver:
            try:
                q = f"{label} {ver}"
                api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                cve_r = await client.get(api, params={"keywordSearch": q, "resultsPerPage": 5}, timeout=10)
                if cve_r.status_code == 200:
                    data = cve_r.json()
                    for item in data.get("vulnerabilities", [])[:5]:
                        cve = item["cve"]
                        cid = cve["id"]
                        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
                        metrics = cve.get("metrics", {})
                        score = None
                        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            if k in metrics and metrics[k]:
                                score = metrics[k][0]["cvssData"].get("baseScore")
                                break
                        sev = Severity.LOW
                        if score:
                            if score >= 9: sev = Severity.CRITICAL
                            elif score >= 7: sev = Severity.HIGH
                            elif score >= 4: sev = Severity.MEDIUM
                        ctx.add(Finding(
                            module=NAME,
                            title=f"Возможная CVE для {label} {ver}: {cid}",
                            severity=sev, cvss=score,
                            description=(f"В базе NVD найдена уязвимость для версии «{label} {ver}». "
                                         f"Описание (англ.): {desc[:400]}"),
                            references=[f"https://nvd.nist.gov/vuln/detail/{cid}"],
                            remediation=f"Проверьте, действительно ли используется уязвимая версия. "
                                        f"Обновите {label} до последней стабильной версии. "
                                        "Если обновление невозможно — изучите раздел Mitigations в карточке CVE.",
                        ))
            except Exception:
                pass
