"""Read-only поиск чувствительных файлов с soft-404 baseline и rate limit."""
from __future__ import annotations

import asyncio
import hashlib
import re
import time
from pathlib import Path
from urllib.parse import urljoin

import httpx

from ..core import Finding, ScanContext, Severity, page_signature, similarity

NAME = "exposures"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False

_ENV_RE = re.compile(rb"(?m)^[A-Z][A-Z0-9_]{1,40}\s*=\s*[^\r\n]{1,200}")
_GIT_HEAD_RE = re.compile(rb"(?m)^ref: refs/(heads|remotes)/[A-Za-z0-9_./-]+\s*$")
_SQL_RE = re.compile(rb"(?i)\b(CREATE\s+TABLE|INSERT\s+INTO|CREATE\s+DATABASE)\b")


class _RateGate:
    def __init__(self, rate: float, *, enabled: bool = True) -> None:
        self.enabled = enabled
        self.interval = 1.0 / max(rate, 0.1)
        self.lock = asyncio.Lock()
        self.last = 0.0

    async def wait(self) -> None:
        if not self.enabled:
            return
        async with self.lock:
            delay = self.interval - (time.monotonic() - self.last)
            if delay > 0:
                await asyncio.sleep(delay)
            self.last = time.monotonic()


def _wordlist() -> list[str]:
    path = Path(__file__).resolve().parents[1] / "data" / "exposures.txt"
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


async def _sample(client: httpx.AsyncClient, url: str, gate: _RateGate) -> tuple[int, bytes, str] | None:
    await gate.wait()
    try:
        async with client.stream("GET", url, headers={"Range": "bytes=0-16383"},
                                 follow_redirects=False) as response:
            chunks = []
            size = 0
            async for chunk in response.aiter_bytes():
                remaining = 16384 - size
                if remaining <= 0:
                    break
                piece = chunk[:remaining]
                chunks.append(piece)
                size += len(piece)
                if size >= 16384:
                    break
            body = b"".join(chunks)
            return response.status_code, body, response.headers.get("content-type", "")
    except Exception:
        return None


def _soft404(candidate: tuple[int, bytes, str], baseline: tuple[int, bytes, str] | None) -> bool:
    if not baseline or candidate[0] != baseline[0]:
        return False
    return similarity(page_signature(candidate[1].decode("utf-8", errors="ignore")),
                      page_signature(baseline[1].decode("utf-8", errors="ignore")), tol=0.06)


def _classify(path: str, status: int, body: bytes, content_type: str) -> tuple[str, Severity, str] | None:
    if status not in {200, 206} or not body:
        return None
    name = path.lower().lstrip("/")
    if name in {".git/head", ".git/refs/heads/main", ".git/refs/heads/master"} and _GIT_HEAD_RE.search(body):
        return "Доступен внутренний файл Git: " + path, Severity.HIGH, "Закройте .git от веб-доступа и проверьте историю репозитория на секреты."
    if name.startswith(".git/") and (b"[core]" in body or b"ref: refs/" in body or body.startswith(b"DIRC")):
        return "Похоже, доступен файл репозитория Git: " + path, Severity.HIGH, "Запретите публикацию каталога .git; при утечке секретов отзовите их."
    if name.startswith(".svn/") and (b"dir\n" in body or b"svn:" in body.lower()):
        return "Похоже, доступен служебный файл SVN: " + path, Severity.HIGH, "Закройте .svn от веб-доступа и проверьте версионную историю."
    if name.startswith(".env") and _ENV_RE.search(body):
        return "Возможная утечка конфигурации / .env: " + path, Severity.HIGH, "Срочно отзовите найденные секреты и запретите выдачу конфигурационных файлов."
    if name.endswith((".sql", ".sql.gz")) and (_SQL_RE.search(body) or body.startswith(b"\x1f\x8b")):
        return "Похоже, опубликован SQL-дамп: " + path, Severity.HIGH, "Уберите дамп из web-root, оцените раскрытые данные и смените скомпрометированные секреты."
    if name == ".ds_store" and body.startswith(b"Bud1"):
        return "Доступен служебный файл .DS_Store", Severity.MEDIUM, "Удалите .DS_Store из публичных каталогов; он может раскрыть имена файлов."
    if name in {"phpinfo.php", "info.php", "phpinfo"} and (b"php version" in body.lower() or b"phpinfo()" in body.lower()):
        return "Публично доступна страница PHP-информации", Severity.MEDIUM, "Отключите phpinfo и удалите диагностические страницы с production."
    if name in {"actuator/heapdump", "heapdump"} and body:
        return "Публично доступен потенциальный heap dump", Severity.HIGH, "Закройте actuator endpoints аутентификацией и сетевыми ACL; проверьте содержимое на секреты."
    if name in {"swagger.json", "openapi.json", "v2/api-docs", "v3/api-docs", "api-docs"} and (
        b'"openapi"' in body or b'"swagger"' in body
    ):
        return "Публична спецификация OpenAPI/Swagger", Severity.INFO, "Проверьте спецификацию на внутренние endpoints и чувствительные примеры; ограничьте доступ, если она не публичная."
    if name.endswith((".zip", ".7z", ".rar", ".tar", ".tgz", ".gz")) and body.startswith((b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c")):
        return "Публично доступен архив: " + path, Severity.MEDIUM, "Удалите резервные копии из web-root или вынесите их в закрытое хранилище."
    if name in {"credentials.json", "secrets.json", ".aws/credentials", "id_rsa", "id_ed25519"}:
        if b"PRIVATE KEY" in body or b"aws_access_key_id" in body.lower() or b'"secret' in body.lower():
            return "Возможна утечка файла с credentials: " + path, Severity.HIGH, "Немедленно отзовите ключи/credentials и закройте файл от публичного доступа."
    if name.endswith((".map",)) and b'"sources"' in body and b'"version"' in body:
        return "Публична карта исходников (source map): " + path, Severity.LOW, "Проверьте source map на внутренний код и случайно встроенные секреты."
    if name in {".gitignore", "composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "pipfile.lock", "readme.md", "changelog.md"}:
        return "Публичен вспомогательный файл проекта: " + path, Severity.LOW, "Убедитесь, что файл не раскрывает внутреннюю информацию или версии уязвимых зависимостей."
    # Generic matching content should not turn arbitrary 200 responses into findings.
    return None


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    if not ctx.permissions.get("intrusive"):
        return
    paths = _wordlist()
    max_paths = max(1, min(150, int(ctx.config.get("exposure_max_paths", 150))))
    paths = paths[:max_paths]
    rate = float(ctx.config.get("rate_limit", 10.0))
    gate = _RateGate(rate, enabled=not ctx.config.get("_client_rate_limited", False))
    baseline_path = f"/.mortyscan-{time.time_ns():x}-not-found"
    baseline = await _sample(client, urljoin(ctx.base_url, baseline_path), gate)
    semaphore = asyncio.Semaphore(20)
    found: set[str] = set()

    async def check(path: str) -> None:
        async with semaphore:
            url = urljoin(ctx.base_url.rstrip("/") + "/", path.lstrip("/"))
            sample = await _sample(client, url, gate)
        if sample is None or _soft404(sample, baseline):
            return
        result = _classify(path, *sample)
        if not result:
            return
        title, severity, remediation = result
        if title in found:
            return
        found.add(title)
        ctx.add(Finding(
            module=NAME, title=title, severity=severity,
            cwe="CWE-538" if severity >= Severity.HIGH else "CWE-200",
            url=url,
            evidence=f"HTTP {sample[0]}; Content-Type={sample[2] or '(не указан)'}; "
                     f"образец={len(sample[1])} байт; SHA-256={hashlib.sha256(sample[1]).hexdigest()}",
            description="По сигнатуре ответа найден возможный забытый файл или открытая спецификация. "
                        "Статус HTTP и имя пути сами по себе не считались подтверждением.",
            remediation=remediation, source="HTTP GET signature", confidence="medium",
            tags=["exposure", path.split("/", 1)[0]],
        ))

    await asyncio.gather(*(check(path) for path in paths))
    ctx.add(Finding(
        module=NAME,
        title=f"Проверка чувствительных файлов завершена: путей {len(paths)}",
        severity=Severity.INFO,
        description="Выполнены только ограниченные GET-запросы; содержимое ответов анализировалось максимум до 16 KiB.",
        raw={"paths_checked": len(paths), "findings": len(found), "rate_limit_per_second": rate},
    ))
