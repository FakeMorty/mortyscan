"""Smoke-тесты: запускаем встроенную лабу и проверяем,
что сканер реально находит ключевые уязвимости."""
from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mortyscan.ethics import Authorization
from mortyscan.runner import run_scan


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


@pytest.fixture(scope="module")
def lab():
    port = _free_port()
    code = (ROOT / "lab" / "vuln_app.py").read_text().replace(
        "port=5055", f"port={port}"
    )
    tmp = ROOT / "lab" / f"_tmp_app_{port}.py"
    tmp.write_text(code)
    proc = subprocess.Popen(
        [sys.executable, str(tmp)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(40):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.1)
    yield port
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired: proc.kill()
    tmp.unlink(missing_ok=True)


def test_full_scan_finds_critical_vulns(lab, tmp_path):
    port = lab
    auth = Authorization(
        target=f"127.0.0.1:{port}",
        owner_or_authorized=True,
        allow_intrusive=True,
        allow_stress=False,
    )
    ctx = asyncio.run(run_scan(
        target=f"http://127.0.0.1:{port}",
        auth=auth,
        case_dir=tmp_path,
        modules_filter={"headers", "crawler", "discovery", "vulns", "tech"},
        config={"crawl_max": 40, "crawl_depth": 3},
        timeout=8.0, verify_tls=False,
    ))

    titles = [f.title for f in ctx.findings]
    blob = "\n".join(titles)

    assert "SQL-инъекция" in blob, f"не нашли SQLi. Находки:\n{blob}"
    assert "XSS" in blob, f"не нашли XSS. Находки:\n{blob}"
    assert "Локальное чтение файлов" in blob, f"не нашли LFI. Находки:\n{blob}"
    assert any("утечка секрета" in t for t in titles), f"не нашли утечку секрета. Находки:\n{blob}"
    assert any("/.env" in t for t in titles), f"не нашли .env. Находки:\n{blob}"
    assert ctx.verdict() in ("HIGH", "CRITICAL", "APOCALYPTIC")


def test_verdict_localization(lab, tmp_path):
    """Проверяем, что вердикт переводится на русский."""
    auth = Authorization(
        target=f"127.0.0.1:{lab}",
        owner_or_authorized=True, allow_intrusive=True,
    )
    ctx = asyncio.run(run_scan(
        target=f"http://127.0.0.1:{lab}", auth=auth, case_dir=tmp_path,
        modules_filter={"headers"}, config={"crawl_max": 1},
        timeout=5.0, verify_tls=False,
    ))
    # Должен быть русский вердикт
    assert ctx.verdict_ru() in {
        "ЧИСТО", "НИЗКИЙ РИСК", "СРЕДНИЙ РИСК",
        "ВЫСОКИЙ РИСК", "КРИТИЧЕСКИЙ РИСК", "КАТАСТРОФА",
    }


def test_report_files_created(lab, tmp_path):
    auth = Authorization(
        target=f"127.0.0.1:{lab}",
        owner_or_authorized=True, allow_intrusive=True,
    )
    asyncio.run(run_scan(
        target=f"http://127.0.0.1:{lab}", auth=auth, case_dir=tmp_path,
        modules_filter={"headers", "crawler"},
        config={"crawl_max": 5},
        timeout=5.0, verify_tls=False,
    ))
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.html").exists()
    # PDF может не создаться, если нет fpdf — это не критично
    # но HTML должен быть на русском
    html_text = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "ВЕРДИКТ" in html_text
    assert "lang=\"ru\"" in html_text
    assert "Серьёзность" not in html_text or "СРЕДНЯЯ" in html_text or "НИЗКАЯ" in html_text or "ИНФО" in html_text
