"""Подбор скрытых путей со списком слов, baseline soft-404 и классификацией содержимого."""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from urllib.parse import urljoin

import httpx

from ..core import Finding, ScanContext, Severity, page_signature, rand_str, similarity

NAME = "discovery"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False


async def _baseline(client: httpx.AsyncClient, base: str) -> dict:
    probes = []
    for _ in range(3):
        p = f"/{rand_str(16)}/{rand_str(8)}.{rand_str(3)}"
        try:
            r = await client.get(urljoin(base, p))
            probes.append({
                "status": r.status_code,
                "sig": page_signature(r.text),
                "loc": r.headers.get("location", ""),
            })
        except Exception:
            pass
    return {"probes": probes}


def _looks_like_baseline(resp_status: int, sig: dict, loc: str, baseline: dict) -> bool:
    for p in baseline.get("probes", []):
        if p["status"] == resp_status and similarity(sig, p["sig"], tol=0.10):
            return True
        if loc and p.get("loc") and loc == p["loc"]:
            return True
    return False


async def _load_wordlist() -> list[str]:
    path = Path(__file__).parent.parent / "data" / "wordlist.txt"
    if not path.exists():
        return []
    return [
        l.strip() for l in path.read_text().splitlines()
        if l.strip() and not l.startswith("#")
    ]


SENSITIVE = {
    ".env", ".git/config", ".git/HEAD", ".git/index", "backup.sql", "backup.zip",
    "dump.sql", "config.php.bak", "wp-config.php.bak", "id_rsa", ".aws/credentials",
    "actuator/env", "actuator/heapdump", "phpinfo.php", "info.php",
    ".env.bak", ".env.prod", ".env.production", "database.sql", "db.sql",
    "dump.zip", "backup.tar.gz", "db.sqlite", "dump.sqlite", "export.csv",
}

AGGRESSIVE_EXTRA_WORDS = {
    ".svn/entries", ".DS_Store", ".gitignore", ".gitlab-ci.yml", ".github/workflows/ci.yml",
    "docker-compose.yml", "Dockerfile", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "package.json", "composer.lock", "web.config", "config.yml", "config.yaml", "settings.py",
    "local.settings.json", "swagger.json", "swagger.yaml", "openapi.json", "api-docs",
    "swagger-ui/", "v2/api-docs", "v3/api-docs", "actuator/health", "actuator/prometheus",
    "metrics", "server-status", "nginx_status", "debug", "debug/default/view", "console/",
    "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "storage/logs/laravel.log",
    "error.log", "access.log", "backup.tar", "backup.gz", "backup.rar", "db.json",
    "users.csv", "export.json", "dump.tar.gz", "app.js.map", "main.js.map", "bundle.js.map",
}

_SQL_RE = re.compile(r"\b(CREATE\s+TABLE|INSERT\s+INTO|ALTER\s+TABLE|DROP\s+TABLE)\b", re.I)
_ENV_RE = re.compile(r"(?m)^(APP_KEY|DB_HOST|DB_NAME|DB_USER|DB_PASSWORD|AWS_[A-Z_]+|STRIPE_[A-Z_]+|SECRET_KEY)\s*=\s*.+$")
_CSV_SENSITIVE_RE = re.compile(r"\b(email|phone|password|hash|token|passport|inn|snils)\b", re.I)
_JSON_SENSITIVE_RE = re.compile(r'"(email|phone|password|password_hash|token|secret|apikey|api_key)"\s*:', re.I)


async def _sample_content(client: httpx.AsyncClient, url: str) -> tuple[bytes, str]:
    headers = {"Range": "bytes=0-4095"}
    try:
        async with client.stream("GET", url, headers=headers) as r:
            chunks = []
            async for chunk in r.aiter_bytes():
                if chunk:
                    chunks.append(chunk)
                if sum(len(x) for x in chunks) >= 4096:
                    break
            data = b"".join(chunks)[:4096]
            ctype = r.headers.get("content-type", "")
            return data, ctype
    except Exception:
        return b"", ""


def _classify_content(path: str, sample: bytes, content_type: str, full_text_hint: str = "") -> dict:
    if not sample and not full_text_hint:
        return {}

    text = full_text_hint or sample.decode("utf-8", errors="ignore")
    low_path = path.lower().lstrip("/")
    ctype = (content_type or "").lower()

    if sample.startswith(b"SQLite format 3"):
        return {
            "kind": "sqlite_db",
            "label": "SQLite база данных",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-538",
            "reason": "Файл начинается с сигнатуры SQLite format 3.",
        }
    if sample.startswith(b"PK\x03\x04"):
        return {
            "kind": "archive_zip",
            "label": "архив ZIP",
            "severity": Severity.HIGH,
            "cwe": "CWE-548",
            "reason": "Файл выглядит как ZIP-архив. Внутри часто лежат бэкапы и экспорты.",
        }
    if sample.startswith(b"\x1f\x8b\x08"):
        return {
            "kind": "archive_gzip",
            "label": "архив GZip",
            "severity": Severity.HIGH,
            "cwe": "CWE-548",
            "reason": "Файл выглядит как GZip-архив. Внутри может быть дамп или бэкап.",
        }
    if "-----BEGIN " in text and "PRIVATE KEY-----" in text:
        return {
            "kind": "private_key",
            "label": "приватный ключ",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-798",
            "reason": "В содержимом виден блок PRIVATE KEY.",
        }
    if _ENV_RE.search(text) or low_path.endswith(".env"):
        return {
            "kind": "env_config",
            "label": "env/config с секретами",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-538",
            "reason": "Похоже на конфигурационный файл с переменными окружения и секретами.",
        }
    if _SQL_RE.search(text) or "phpmyadmin sql dump" in text.lower() or low_path.endswith(".sql"):
        return {
            "kind": "sql_dump",
            "label": "SQL-дамп / экспорт БД",
            "severity": Severity.CRITICAL,
            "cwe": "CWE-538",
            "reason": "В содержимом видны SQL-конструкции CREATE TABLE / INSERT INTO или расширение .sql.",
        }
    if ("index of /" in text.lower() or "directory listing" in text.lower()) and "text/html" in ctype:
        return {
            "kind": "dir_listing",
            "label": "листинг директории",
            "severity": Severity.MEDIUM,
            "cwe": "CWE-548",
            "reason": "Страница похожа на открытый список файлов в директории.",
        }
    if (low_path.endswith(".map") or "application/json" in ctype) and '"sources"' in text and '"version"' in text:
        return {
            "kind": "source_map",
            "label": "source map",
            "severity": Severity.MEDIUM,
            "cwe": "CWE-200",
            "reason": "Файл похож на source map и может раскрывать внутренние пути и исходники.",
        }
    if low_path.endswith(".csv") and _CSV_SENSITIVE_RE.search(text[:1000]):
        return {
            "kind": "csv_export",
            "label": "CSV-экспорт с чувствительными полями",
            "severity": Severity.HIGH,
            "cwe": "CWE-359",
            "reason": "В CSV-колонках встречаются email/phone/password/hash/token и т.п.",
        }
    if (low_path.endswith(".json") or "application/json" in ctype) and _JSON_SENSITIVE_RE.search(text[:4000]):
        return {
            "kind": "json_export",
            "label": "JSON-экспорт с чувствительными полями",
            "severity": Severity.HIGH,
            "cwe": "CWE-359",
            "reason": "JSON содержит ключи вроде email/password_hash/token/secret.",
        }
    if low_path.endswith(("swagger.json", "openapi.json")) or "/api-docs" in low_path:
        return {
            "kind": "api_schema",
            "label": "публичная схема API / Swagger / OpenAPI",
            "severity": Severity.MEDIUM,
            "cwe": "CWE-200",
            "reason": "Путь похож на опубликованную спецификацию API. Это удобно разработчикам, но также сильно помогает атакующему картировать поверхность приложения.",
        }
    if low_path.endswith(".ds_store"):
        return {
            "kind": "ds_store",
            "label": "служебный файл .DS_Store",
            "severity": Severity.MEDIUM,
            "cwe": "CWE-200",
            "reason": "Файл .DS_Store может раскрывать имена скрытых файлов и структуру каталога.",
        }
    if low_path.endswith("composer.json"):
        return {
            "kind": "dependency_manifest",
            "label": "манифест зависимостей",
            "severity": Severity.LOW,
            "cwe": "CWE-200",
            "reason": "composer.json раскрывает стек и зависимости приложения.",
        }
    return {}


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    if not ctx.permissions.get("intrusive"):
        ctx.add(Finding(
            module=NAME,
            title="Подбор путей пропущен (нет разрешения на активный скан)",
            severity=Severity.INFO,
        ))
        return

    base = ctx.base_url
    baseline = await _baseline(client, base)
    ctx.baseline_404 = baseline

    words = await _load_wordlist()
    if ctx.config.get("aggressive"):
        words = sorted(set(words) | AGGRESSIVE_EXTRA_WORDS)
    sem = asyncio.Semaphore(40 if ctx.config.get("aggressive") else 20)
    hits: list[tuple[str, int, int]] = []

    async def check(w: str):
        url = urljoin(base + "/", w.lstrip("/"))
        async with sem:
            try:
                r = await client.get(url)
            except Exception:
                return

        sig = page_signature(r.text)
        loc = r.headers.get("location", "")
        if r.status_code in (404,):
            return
        if _looks_like_baseline(r.status_code, sig, loc, baseline):
            return
        if r.status_code not in (200, 201, 204, 301, 302, 401, 403, 500):
            return

        hits.append((w, r.status_code, sig["len"]))
        sev = Severity.LOW
        human = ""
        fix = None
        cwe = None
        confidence = None
        sample_kind = None

        if r.status_code == 200:
            sample, ctype = await _sample_content(client, url)
            preview_text = (r.text or "")[:4096] if len(r.text or "") <= 4096 else ""
            classified = _classify_content("/" + w, sample, ctype, full_text_hint=preview_text)
            if classified:
                sample_kind = classified.get("kind")
                sev = classified.get("severity", Severity.LOW)
                cwe = classified.get("cwe")
                confidence = "high"
                human = f" Похоже на {classified.get('label')}. {classified.get('reason')}"
                if sev >= Severity.HIGH:
                    fix = (
                        "Удалите или вынесите файл из web-root. Закройте доступ на уровне веб-сервера, "
                        "не храните бэкапы/экспорты/секреты в публичной директории."
                    )

        if w in SENSITIVE and r.status_code in (200, 301, 302):
            sev = max(sev, Severity.CRITICAL)
            cwe = cwe or "CWE-538"
            confidence = confidence or "medium"
            if not human:
                human = " Это критично: открыт служебный или резервный файл, не предназначенный для публичного доступа."
            fix = fix or (
                "Удалите файл с веб-сервера. Настройте веб-сервер блокировать доступ "
                "к скрытым/служебным файлам (`.*`, `*.bak`, `*.sql`, `.git/`)."
            )
        elif r.status_code in (401, 403):
            sev = Severity.INFO
            human = " (требует авторизации — это нормально)"
        elif r.status_code == 500:
            sev = Severity.MEDIUM
            human = " — сервер вернул ошибку. Это может указывать на необработанное исключение."
            fix = "Найдите причину 500 в логах. Не показывайте трассировку пользователям."

        title = f"Найден путь: /{w} (код {r.status_code})"
        if sample_kind and sev >= Severity.HIGH:
            title = f"Публично доступен чувствительный файл: /{w} (код {r.status_code})"

        ctx.add(Finding(
            module=NAME,
            title=title,
            severity=sev,
            url=url,
            description=f"Статус {r.status_code}, длина ответа {sig['len']} байт.{human}",
            cwe=cwe,
            remediation=fix,
            confidence=confidence,
            source="wordlist + content classifier" if sample_kind else "wordlist",
            category="exposed_file" if sev >= Severity.HIGH else None,
            raw={"path": "/" + w, "status": r.status_code, "sample_kind": sample_kind},
        ))

    await asyncio.gather(*(check(w) for w in words))

    ctx.add(Finding(
        module=NAME,
        title=f"Подбор путей завершён: найдено {len(hits)} интересных",
        severity=Severity.INFO,
        raw={"hits": hits},
    ))
