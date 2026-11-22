from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.core import Finding, ScanContext, Severity
from mortyscan.reporting.report import write_html, write_json, write_pdf


def test_report_urls_drop_query_values_across_formats(tmp_path: Path):
    secret = "access_token=do-not-publish"
    ctx = ScanContext(target="example.com", base_url="https://example.com")
    ctx.crawled_urls.add("https://example.com/profile?" + secret)
    ctx.script_urls.add("https://example.com/app.js?" + secret)
    ctx.endpoints.add("https://example.com/api?" + secret)
    ctx.site_info = {"http": {"final_url": "https://example.com/home?" + secret}}
    ctx.add(Finding(module="test", title="safe", severity=Severity.INFO,
                    url="https://example.com/route?" + secret))

    json_path = write_json(ctx, tmp_path / "report.json")
    html_path = write_html(ctx, tmp_path / "report.html")
    pdf_path = write_pdf(ctx, tmp_path / "report.pdf")
    assert secret not in json_path.read_text()
    assert secret not in html_path.read_text()
    assert secret.encode() not in pdf_path.read_bytes()
    payload = json.loads(json_path.read_text())
    assert payload["api_endpoints"] == ["https://example.com/api"]
    assert payload["находки"][0]["url"] == "https://example.com/route"
