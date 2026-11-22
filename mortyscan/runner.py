"""Оркестратор сканирования."""
from __future__ import annotations

import asyncio
import logging
import socket
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import __version__
from .core import ScanContext, host_in_scope, make_client
from .ethics import Authorization
from .i18n import SEVERITY_RU
from .modules import (
    auth,
    browser,
    cors_audit,
    csrf_audit,
    crawler,
    exposures,
    enrich,
    chain,
    export,
    js_deep,
    subdomain_deep,
    discovery,
    dalfox,
    graphql,
    graphql_deep,
    headers,
    jwt_audit,
    local_arp,
    methods,
    ports,
    redirect,
    recon,
    siteinfo,
    sqlmap,
    stress,
    takeover,
    tech,
    tls,
    tls_deep,
    vulns,
    waf,
    nuclei,
    oast,
    openapi,
)
from .reporting.report import write_html, write_json, write_pdf

console = Console()
LOG = logging.getLogger("mortyscan")

# Порядок имеет значение: пассивные → активные. crawler должен предшествовать аудитам форм и vulns/discovery.
ALL_MODULES = [
    ("auth",       auth,       "Форма входа и проверка сессии (если задана)"),
    ("recon",      recon,      "Разведка DNS / сабдомены"),
    ("subdomain_deep", subdomain_deep, "Глубокая DNS-энумерация поддоменов"),
    ("siteinfo",    siteinfo,   "Сведения о сайте / IP / ASN / регистратор"),
    ("waf",        waf,        "Пассивный fingerprint WAF/CDN"),
    ("headers",    headers,    "HTTP-заголовки / cookies / CORS"),
    ("methods",    methods,    "HTTP-методы / TRACE / WebDAV"),
    ("tls",        tls,        "TLS / сертификат"),
    ("tls_deep",   tls_deep,   "Глубокий TLS-анализ SSLyze (только по флагу)"),
    ("tech",       tech,       "Технологии и CVE"),
    ("ports",      ports,      "TCP-порты (требует --active)"),
    ("crawler",    crawler,    "Краулер сайта"),
    ("exposures",  exposures,  "Проверка чувствительных файлов"),
    ("redirect",   redirect,   "Проверка Open Redirect"),
    ("csrf_audit", csrf_audit, "Проверка CSRF-защиты форм"),
    ("graphql",    graphql,    "GraphQL"),
    ("graphql_deep", graphql_deep, "GraphQL type-suggestions (опционально load test)"),
    ("discovery",  discovery,  "Подбор скрытых путей"),
    ("vulns",      vulns,      "Тестирование уязвимостей"),
    ("sqlmap",     sqlmap,     "Подтверждение SQLi через SQLMap (только по флагу)"),
    ("dalfox",     dalfox,     "Глубокая XSS-проверка Dalfox (только по флагу)"),
    ("browser",    browser,    "SPA / DOM-XSS браузерная проверка (только по флагу)"),
    ("js_deep",    js_deep,    "Глубокий анализ JavaScript/source maps"),
    ("openapi",    openapi,    "Read-only REST API проверка по OpenAPI (только по флагу)"),
    ("cors_audit", cors_audit, "Активная проверка CORS endpoint'ов"),
    ("nuclei",       nuclei,     "Внешняя проверка Nuclei (только по флагу)"),
    ("jwt",        jwt_audit,  "Аудит JWT-токенов"),
    ("takeover",   takeover,   "Захват сабдоменов"),
    ("local_arp",  local_arp,  "ARP-скан локальной сети"),
    ("stress",     stress,     "Нагрузочный (стресс) тест"),
    ("oast",       oast,       "Явные read-only Interactsh OAST probes"),
    ("enrich",     enrich,     "EPSS / CISA KEV / OSV enrichment (только по флагу)"),
    ("chain",      chain,      "Корреляция findings в attack paths по YAML-правилам"),
    ("export",     export,     "SARIF / DefectDojo / report diff export"),
]


def _normalize_target(raw: str) -> tuple[str, str]:
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    from urllib.parse import urlparse
    p = urlparse(raw)
    host = p.hostname or raw
    base = f"{p.scheme}://{host}" + (f":{p.port}" if p.port else "")
    return host, base


async def _resolve(host: str) -> Optional[str]:
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, socket.gethostbyname, host)
    except Exception:
        return None


async def run_scan(target: str, auth: Authorization, *,
                   case_dir: Path,
                   modules_filter: Optional[set[str]] = None,
                   config: Optional[dict] = None,
                   timeout: float = 10.0,
                   verify_tls: bool = True,
                   proxy: Optional[str] = None) -> ScanContext:
    host, base = _normalize_target(target)
    ctx = ScanContext(target=host, base_url=base, case_dir=case_dir)
    ctx.permissions = {
        "intrusive": auth.allow_intrusive,
        "stress": auth.allow_stress,
        "local_arp": auth.allow_local_arp,
    }
    if config:
        ctx.config.update(config)
    ctx.config["_client_rate_limited"] = True
    scope_hosts = {str(item).strip().lower() for item in ctx.config.get("scope_hosts", []) if str(item).strip()}
    if scope_hosts and not host_in_scope(host, scope_hosts):
        raise ValueError(f"Цель {host} не входит в --scope-file")
    ctx.ip = await _resolve(host)

    case_dir.mkdir(parents=True, exist_ok=True)

    console.rule(f"[bold magenta]MortyScan v{__version__} → {host} ({ctx.ip or 'не разрешено'})")

    perms_human = []
    perms_human.append(("активные пробы", "ДА" if ctx.permissions["intrusive"] else "нет"))
    perms_human.append(("стресс-тест", "ДА" if ctx.permissions["stress"] else "нет"))
    perms_human.append(("ARP-скан LAN", "ДА" if ctx.permissions["local_arp"] else "нет"))
    tbl = Table(show_header=False, box=None, padding=(0, 1))
    for k, v in perms_human:
        tbl.add_row(
            f"  [dim]{k}:[/dim]",
            f"[green]{v}[/green]" if v == "ДА" else f"[dim]{v}[/dim]",
        )
    console.print(tbl)

    extra_headers: dict[str, str] = {}
    for raw_header in ctx.config.get("request_headers", []):
        raw_header = str(raw_header)
        name, separator, value = raw_header.partition(":")
        if not separator or not name.strip() or "\r" in raw_header or "\n" in raw_header:
            raise ValueError(f"Некорректный HTTP-заголовок: {raw_header!r}")
        extra_headers[name.strip()] = value.strip()
    if ctx.config.get("cookie"):
        cookie_value = str(ctx.config["cookie"])
        if "\r" in cookie_value or "\n" in cookie_value:
            raise ValueError("Cookie must not contain CR/LF characters")
        extra_headers["Cookie"] = cookie_value

    async with make_client(
        timeout=timeout, verify=verify_tls, proxy=proxy,
        extra_headers=extra_headers, auth_host=host, auth_origin=base,
        scope_hosts=scope_hosts, rate_limit=float(ctx.config.get("rate_limit", 10.0)),
    ) as client:
        for _ in range(4):
            try:
                await client.get(base)
                break
            except Exception:
                await asyncio.sleep(0.25)
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            for name, mod, human in ALL_MODULES:
                if (modules_filter and name not in modules_filter
                        and name not in {"auth", "chain", "export"}
                        and not (name == "oast" and ctx.config.get("oast_enabled"))):
                    continue
                if getattr(mod, "REQUIRES_STRESS", False) and not ctx.permissions.get("stress"):
                    continue
                if scope_hosts and name == "local_arp":
                    console.print("[yellow]local_arp пропущен: scope-файл не задаёт разрешённую локальную сеть[/yellow]")
                    continue
                if getattr(mod, "REQUIRES_INTRUSIVE", False) and not ctx.permissions.get("intrusive"):
                    if name == "vulns":
                        try:
                            await mod.run(ctx, client)
                        except Exception:
                            pass
                    continue
                task_id = progress.add_task(f"Модуль: {human}", total=None)
                try:
                    await mod.run(ctx, client)
                except Exception as e:
                    LOG.exception("модуль %s упал", name)
                    console.print(f"[red]модуль {name} упал:[/red] {e}")
                progress.update(task_id, completed=1, total=1)
                progress.stop_task(task_id)

    sev_counts = {}
    for f in ctx.findings:
        sev_counts[f.severity.label] = sev_counts.get(f.severity.label, 0) + 1
    console.rule("[bold green]Сканирование завершено")

    sumtbl = Table(title="Итог", show_lines=False)
    sumtbl.add_column("Серьёзность")
    sumtbl.add_column("Кол-во", justify="right")
    for lab in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = sev_counts.get(lab, 0)
        if n:
            sumtbl.add_row(
                f"[{ {'CRITICAL':'red bold','HIGH':'red','MEDIUM':'yellow','LOW':'blue','INFO':'cyan'}[lab] }]{SEVERITY_RU[lab]}[/]",
                str(n),
            )
    sumtbl.add_row("[bold]Очки риска[/bold]", f"[bold]{ctx.risk_score()}[/bold]")
    sumtbl.add_row(
        "[bold]Вердикт[/bold]",
        f"[bold red]{ctx.verdict_ru()}[/bold red]" if ctx.risk_score() >= 100
        else f"[bold]{ctx.verdict_ru()}[/bold]",
    )
    console.print(sumtbl)

    json_path = case_dir / "report.json"
    write_json(ctx, json_path)
    html_path = case_dir / "report.html"
    write_html(ctx, html_path)
    pdf_path = case_dir / "report.pdf"
    write_pdf(ctx, pdf_path)
    console.print(f"\n[green]Отчёты сохранены в каталог:[/green] {case_dir}/")
    console.print(f"  • [bold]JSON[/bold] (для интеграций): [cyan]{json_path}[/cyan]")
    console.print(f"  • [bold]HTML[/bold] (открыть в браузере): [cyan]{html_path}[/cyan]")
    if pdf_path and pdf_path.exists():
        console.print(f"  • [bold]PDF[/bold] (для печати): [cyan]{pdf_path}[/cyan]")
    sarif_path = ctx.config.get("sarif_path")
    if sarif_path:
        console.print(f"  • [bold]SARIF[/bold]: [cyan]{sarif_path}[/cyan]")

    return ctx
