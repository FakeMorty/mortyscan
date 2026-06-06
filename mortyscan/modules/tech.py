"""Определение технологий + аккуратный поиск известных CVE через NVD."""
from __future__ import annotations

import re
from typing import Any

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

_EOL_RULES: dict[str, tuple[tuple[int, int], Severity]] = {
    "PHP": ((8, 1), Severity.HIGH),
    "WordPress": ((5, 9), Severity.MEDIUM),
}


def _extract_version(text: str) -> str:
    m = re.search(r"([\d]+\.[\d]+(?:\.[\d]+)?)", text or "")
    return m.group(1) if m else ""


def _version_tuple(ver: str) -> tuple[int, ...]:
    out = []
    for part in re.findall(r"\d+", ver or "")[:3]:
        out.append(int(part))
    return tuple(out)


def _is_eol(label: str, ver: str) -> bool:
    rule = _EOL_RULES.get(label)
    if not rule or not ver:
        return False
    cutoff, _ = rule
    current = _version_tuple(ver)
    if not current:
        return False
    while len(current) < len(cutoff):
        current = current + (0,)
    return current[: len(cutoff)] <= cutoff


def _severity_from_score(score: float | None) -> Severity:
    if not score:
        return Severity.LOW
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW


def _confidence(evidence_count: int, has_version: bool) -> str:
    score = evidence_count + (1 if has_version else 0)
    if score >= 3:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


async def _fetch_cves(client: httpx.AsyncClient, label: str, ver: str) -> list[dict[str, Any]]:
    api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    q = f"{label} {ver}"
    try:
        r = await client.get(api, params={"keywordSearch": q, "resultsPerPage": 10}, timeout=12)
    except Exception:
        return []
    if r.status_code != 200:
        return []
    try:
        data = r.json()
    except Exception:
        return []

    out: list[dict[str, Any]] = []
    for item in data.get("vulnerabilities", [])[:10]:
        cve = item.get("cve", {})
        cid = cve.get("id", "")
        if not cid:
            continue
        desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {}) or {}
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        out.append({
            "id": cid,
            "score": score,
            "description": desc[:300],
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
        })
    return out


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    try:
        r = await client.get(ctx.base_url)
    except Exception:
        return

    body = r.text or ""
    server = r.headers.get("server", "")
    powered = r.headers.get("x-powered-by", "")
    cookies = "; ".join(f"{c.name}={c.value}" for c in r.cookies)

    detected: dict[str, dict[str, Any]] = {}

    for label, hre, bre in RULES:
        ver = ""
        evidence: list[str] = []

        if hre:
            for source_name, hay in (
                ("header:server", server),
                ("header:x-powered-by", powered),
                ("cookie", cookies),
            ):
                if hay and hre.search(hay):
                    evidence.append(f"{source_name}={hay[:120]}")
                    if not ver:
                        ver = _extract_version(hay)

        if bre:
            m = bre.search(body)
            if m:
                evidence.append(f"body:{m.group(0)[:120]}")
                if not ver and m.groups():
                    for g in m.groups():
                        if g and re.match(r"^\d", str(g)):
                            ver = str(g)
                            break

        if not evidence:
            continue

        detected[label] = {
            "version": ver,
            "evidence": evidence,
            "confidence": _confidence(len(evidence), bool(ver)),
        }

    for label, meta in detected.items():
        ver = meta.get("version", "")
        conf = meta.get("confidence", "low")
        sources = meta.get("evidence", [])
        ctx.tech[label] = ver
        title = f"Технология обнаружена: {label}" + (f" {ver}" if ver else "")
        ctx.add(Finding(
            module=NAME,
            title=title,
            severity=Severity.INFO,
            description=(
                "Распознано по заголовкам/телу ответа/cookie. Источники: "
                + "; ".join(sources[:4])
                + (f"; ещё {len(sources) - 4}" if len(sources) > 4 else "")
            ),
            confidence=conf,
            source=", ".join(s.split("=", 1)[0] for s in sources[:4]),
            raw={"evidence": sources},
        ))

        if _is_eol(label, ver):
            sev = _EOL_RULES.get(label, ((0, 0), Severity.HIGH))[1]
            ctx.add(Finding(
                module=NAME,
                title=f"Устаревшая технология (EOL): {label} {ver}",
                severity=sev,
                description=(
                    f"Версия {label} {ver} выглядит устаревшей и, вероятно, уже вышла из поддержки. "
                    "Для таких версий перестают выходить обычные security-обновления, поэтому общий риск резко растёт."
                ),
                remediation=(
                    f"Запланируйте обновление {label} до поддерживаемой стабильной ветки. "
                    "Даже если прямой эксплуатации сейчас не видно, EOL-стек быстро накапливает критические дыры."
                ),
                confidence="medium",
                source="version heuristic",
            ))

        if not ver:
            continue

        cves = await _fetch_cves(client, label, ver)
        if not cves:
            continue

        cves_sorted = sorted(cves, key=lambda x: (x.get("score") or 0, x.get("id") or ""), reverse=True)
        max_score = max((c.get("score") or 0) for c in cves_sorted)
        sev = _severity_from_score(max_score)
        top = cves_sorted[:3]
        refs = [c["url"] for c in top if c.get("url")]
        top_ids = ", ".join(c["id"] for c in top if c.get("id"))
        ctx.add(Finding(
            module=NAME,
            title=f"Для {label} {ver} найдены релевантные CVE: {len(cves_sorted)} шт.",
            severity=sev,
            cvss=max_score or None,
            description=(
                f"По эвристическому поиску в NVD для «{label} {ver}» нашлось {len(cves_sorted)} релевантных записей. "
                f"Самые заметные: {top_ids}. Это НЕ доказательство эксплуатабельности на данном сайте, "
                "а сигнал проверить версию, changelog и применимость патчей."
            ),
            references=refs,
            remediation=(
                f"Проверьте реальную версию {label} на сервере и сверите её с advisories производителя. "
                f"Если версия действительно {ver}, обновите {label} до поддерживаемой ветки."
            ),
            confidence="medium",
            source="NVD keywordSearch",
            raw={"cves": cves_sorted},
            category="cve_match",
        ))
