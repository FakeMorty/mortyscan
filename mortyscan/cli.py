"""Командная строка MortyScan v20 «Deep Attack Platform».

Примеры:
  python -m mortyscan                            # интерактивный мастер
  python -m mortyscan scan example.com           # пассивный аудит
  python -m mortyscan scan example.com --active  # + активные проверки
  python -m mortyscan scan example.com --active --stress --i-own-this-target
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from . import __version__, __codename__
from .core import host_in_scope
from .ethics import interactive_gate, Authorization
from .runner import ALL_MODULES, run_scan

def _default_report_dir() -> Path:
    """Путь к папке отчётов по умолчанию.
    В Termux → ~/storage/downloads/MortyScan (видно в Android).
    В обычной системе → ~/MortyScanReports.
    """
    home = Path.home()
    # Termux: если есть storage/downloads, используем его
    if os.environ.get("TERMUX_VERSION") or (home / "storage" / "downloads").exists():
        d = home / "storage" / "downloads" / "MortyScan"
        d.mkdir(parents=True, exist_ok=True)
        return d
    # Обычная система
    d = home / "MortyScanReports"
    d.mkdir(parents=True, exist_ok=True)
    return d


app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    invoke_without_command=True,
    help=f"MortyScan v{__version__} «{__codename__}» — сканер безопасности сайтов "
         f"для авторизованного тестирования.",
)
console = Console()


WELCOME = """[bold magenta]MortyScan v20 «Deep Attack Platform»[/bold magenta]
Сканер безопасности веб-сайтов на русском языке.

[yellow]Что я умею:[/yellow]
  • Проверить DNS, сертификат, заголовки, HTTP-методы, порты
  • Собрать сведения о сайте: IP, ASN, страна, регистратор, редиректы, CDN/WAF
  • Найти забытые файлы (.env, бэкапы, .git) с проверкой сигнатур и soft-404
  • Пассивно распознать WAF/CDN, проверить Open Redirect и CORS
  • По желанию подключить Nuclei с безопасным набором шаблонов
  • Поймать SQL-инъекции, XSS, LFI, SSRF, открытые редиректы
  • Проверить формы на очевидные маркеры CSRF-защиты — без отправки формы
  • Поискать сабдомены; глубокий DNS-брутифорс — только с --active --deep-subdomains
  • Проверить JavaScript-бандлы, source maps, endpoint'ы и возможные утечки ключей
  • Аудитировать JWT-токены
  • Найти GraphQL и проверить, не выдаёт ли он лишнего
  • Сделать стресс-тест (только с явного согласия)
  • Сгенерировать понятный отчёт с пояснениями
"""


@app.callback()
def _main(
    ctx: typer.Context,
    list_modules: bool = typer.Option(False, "--list-modules", is_eager=True,
                                     help="Вывести список модулей и выйти."),
):
    """Если запустили без подкоманды — открыть мастер."""
    if list_modules:
        list_modules_cmd()
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        wizard()


@app.command("scan")
def scan_cmd(
    target: str = typer.Argument(..., help="Домен или URL, напр. example.com"),
    active: bool = typer.Option(False, "--active/--passive",
                                help="Включить активные проверки (фуззинг, инъекции). "
                                     "Без флага — только пассивный аудит."),
    stress: bool = typer.Option(False, "--stress",
                                help="Включить стресс-тест (нагрузку). "
                                     "Требует --i-own-this-target."),
    arp: bool = typer.Option(False, "--arp", help="Включить ARP-скан локальной сети."),
    own: bool = typer.Option(False, "--i-own-this-target",
                             help="Подтверждаю, что я владелец цели или имею письменное разрешение."),
    yes: bool = typer.Option(False, "--yes", "-y",
                             help="Не задавать интерактивных вопросов (для CI/скриптов)."),
    out: Path = typer.Option(_default_report_dir(), "--out", "-o",
                             help="Каталог для отчётов."),
    modules: Optional[str] = typer.Option(
        None, "--modules",
        help="Список модулей через запятую (auth,recon,subdomain_deep,siteinfo,waf,headers,methods,tls,tls_deep,tech,ports,crawler,js_deep,exposures,redirect,csrf_audit,cors_audit,graphql,discovery,vulns,sqlmap,dalfox,browser,openapi,graphql_deep,nuclei,oast,enrich,chain,export,jwt,takeover,local_arp,stress).",
    ),
    timeout: float = typer.Option(10.0, "--timeout", help="Таймаут на HTTP-запрос, сек."),
    no_verify: bool = typer.Option(False, "--no-verify",
                                   help="Не проверять сертификат TLS (для самоподписных)."),
    proxy: Optional[str] = typer.Option(None, "--proxy",
                                        help="HTTP-прокси, напр. http://127.0.0.1:8080 (Burp)."),
    cookie: Optional[str] = typer.Option(None, "--cookie", help="Cookie для авторизованного аудита; только целевой хост."),
    header: list[str] = typer.Option([], "--header", help="HTTP-заголовок для авторизованного аудита; можно повторять."),
    login_url: Optional[str] = typer.Option(None, "--login-url", help="URL POST-формы входа; должен быть на origin цели."),
    login_creds: Optional[str] = typer.Option(None, "--login-creds", help="Учётные данные аккаунта A в формате user:pass."),
    account_b: Optional[str] = typer.Option(None, "--account-b", help="Второй аккаунт user:pass для BOLA/API-проверок."),
    scope_file: Optional[Path] = typer.Option(None, "--scope-file", help="Файл allowlist доменов/IP; все HTTP-запросы вне scope блокируются."),
    deep_subdomains: bool = typer.Option(False, "--deep-subdomains", help="Включить активный DNS-брутифорс; требует --active."),
    mutate: bool = typer.Option(False, "--mutate", help="Добавить типовые dev/staging/test мутации имён (требует --deep-subdomains)."),
    subdomain_max: int = typer.Option(500, "--subdomain-max", min=1, max=5000, help="Максимум DNS-кандидатов при --deep-subdomains."),
    save_sourcemaps: bool = typer.Option(False, "--save-sourcemaps", help="Локально сохранить sourcesContent; исходники могут содержать секреты."),
    sqlmap_enabled: bool = typer.Option(False, "--sqlmap", help="Явно включить SQLMap для SQLi-кандидатов (требует --active)."),
    dump_data: bool = typer.Option(False, "--dump-data", help="Разрешить SQLMap --dump только после отдельного интерактивного подтверждения."),
    sqlmap_timeout: int = typer.Option(180, "--sqlmap-timeout", min=1, max=180, help="Таймаут SQLMap на один URL (максимум 180 секунд)."),
    sqlmap_extra: Optional[str] = typer.Option(None, "--sqlmap-extra", help="Дополнительные аргументы SQLMap; опасные режимы блокируются."),
    openapi_enabled: bool = typer.Option(False, "--openapi", help="Явно включить OpenAPI REST проверки (требует --active)."),
    nmap_enabled: bool = typer.Option(False, "--nmap", help="Явно запустить Nmap -sV/-sC/NSE по первым 100 портам; требуется --active."),
    nmap_timeout: int = typer.Option(300, "--nmap-timeout", min=10, max=900, help="Общий таймаут Nmap, секунд."),
    tls_deep_enabled: bool = typer.Option(False, "--tls-deep", help="Явно включить глубокие TLS-проверки через optional SSLyze (требует --active)."),
    graphql_deep_enabled: bool = typer.Option(False, "--graphql-deep", help="Включить GraphQL type probes и field suggestions (требует --active)."),
    graphql_load_tests: bool = typer.Option(False, "--graphql-load-tests", help="Разрешить один batch из 100 безопасных __typename aliases после TTY-подтверждения."),
    browser_enabled: bool = typer.Option(False, "--browser", help="Явно включить optional Playwright SPA/DOM-анализ (требует --active)."),
    screenshots: bool = typer.Option(False, "--screenshots", help="Сохранять скриншоты в папке отчёта (требует --browser)."),
    dalfox_enabled: bool = typer.Option(False, "--dalfox", help="Явно включить Dalfox для XSS-кандидатов (требует --active)."),
    dalfox_timeout: int = typer.Option(120, "--dalfox-timeout", min=1, max=180, help="Таймаут Dalfox на URL."),
    oast: bool = typer.Option(False, "--oast", help="Включить ограниченные read-only GET Interactsh probes (явное разрешение обязательно)."),
    oast_write_probes: bool = typer.Option(False, "--oast-write-probes", help="Дополнительно разрешить до двух POST XXE/webhook probes; требует --oast, активной цели и отдельного TTY-подтверждения."),
    interactsh_url: Optional[str] = typer.Option(None, "--interactsh-url", help="Необязательный custom Interactsh server; для Dalfox нужен явный endpoint."),
    enrich_enabled: bool = typer.Option(False, "--enrich", help="Запросить EPSS/KEV/OSV по найденным CVE и опубликованным manifest-файлам; наружу передаются только CVE/package coordinates."),
    sarif_enabled: bool = typer.Option(False, "--sarif", help="Создать локальный SARIF 2.1.0-отчёт."),
    diff_from: Optional[Path] = typer.Option(None, "--diff-from", help="Сравнить с предыдущим report.json."),
    defectdojo_url: Optional[str] = typer.Option(None, "--defectdojo-url", help="HTTPS endpoint или base URL DefectDojo; требует key и engagement ID."),
    defectdojo_key: Optional[str] = typer.Option(None, "--defectdojo-key", help="DefectDojo API key; передаётся только в Authorization header."),
    defectdojo_engagement_id: Optional[int] = typer.Option(None, "--defectdojo-engagement-id", min=1, help="Positive DefectDojo engagement ID для import-scan."),
    nuclei_enabled: bool = typer.Option(False, "--nuclei", help="Явно включить внешний Nuclei (требует --active)."),
    nuclei_tags: Optional[str] = typer.Option(None, "--nuclei-tags", help="Nuclei template tags."),
    nuclei_exclude_tags: Optional[str] = typer.Option(None, "--nuclei-exclude-tags", help="Исключить Nuclei tags."),
    nuclei_templates: Optional[str] = typer.Option(None, "--nuclei-templates", help="Путь к кастомному Nuclei template/directory."),
    nuclei_timeout: int = typer.Option(600, "--nuclei-timeout", help="Общий таймаут Nuclei, секунд."),
    no_external: bool = typer.Option(False, "--no-external", help="Не запускать внешние бинарники."),
    rate_limit: float = typer.Option(10.0, "--rate-limit", min=1.0, max=100.0, help="Лимит HTTP-запросов на хост в секунду; применяется ко всем HTTP-модулям."),
    crawl_max: int = typer.Option(80, "--crawl-max", help="Лимит страниц для краулера."),
    crawl_depth: int = typer.Option(3, "--crawl-depth", help="Глубина краула."),
    aggressive: bool = typer.Option(False, "--aggressive",
                                    help="Более агрессивный, но всё ещё проверочный режим: шире wordlist, "
                                         "дополнительные payload'ы, аудит HTTP-методов/TRACE."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Запустить сканирование."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if stress and not own:
        console.print("[red]Для --stress обязателен флаг --i-own-this-target[/red]")
        raise typer.Exit(2)
    if login_creds and not login_url:
        console.print("[red]Для --login-creds обязателен --login-url[/red]")
        raise typer.Exit(2)
    if account_b and not login_url:
        console.print("[red]Для --account-b обязателен --login-url[/red]")
        raise typer.Exit(2)
    if account_b and not (login_creds or cookie or any(str(item).partition(":")[0].strip().lower() == "authorization" for item in header)):
        console.print("[red]Для BOLA-теста задайте аутентификацию аккаунта A через --login-creds, --cookie или Authorization --header[/red]")
        raise typer.Exit(2)
    if login_url and not (login_creds or account_b):
        console.print("[red]С --login-url укажите --login-creds и/или --account-b[/red]")
        raise typer.Exit(2)
    if login_url and (urlparse(login_url).scheme not in {"http", "https"} or not urlparse(login_url).hostname):
        console.print("[red]--login-url должен быть абсолютным HTTP(S) URL[/red]")
        raise typer.Exit(2)
    if (login_creds or account_b) and not active:
        console.print("[red]Для входа по credentials обязателен --active[/red]")
        raise typer.Exit(2)
    for label, credentials in (("--login-creds", login_creds), ("--account-b", account_b)):
        if credentials and (":" not in credentials or not credentials.partition(":")[0] or not credentials.partition(":")[2]):
            console.print(f"[red]{label} должен иметь формат user:pass[/red]")
            raise typer.Exit(2)

    dd_requested = bool(defectdojo_url or defectdojo_key or defectdojo_engagement_id)
    if dd_requested and not (defectdojo_url and defectdojo_key and defectdojo_engagement_id):
        console.print("[red]DefectDojo export требует --defectdojo-url, --defectdojo-key и --defectdojo-engagement-id[/red]")
        raise typer.Exit(2)
    if defectdojo_url:
        dd_parsed = urlparse(defectdojo_url)
        if (dd_parsed.scheme != "https" or not dd_parsed.hostname or dd_parsed.username
                or dd_parsed.password or dd_parsed.query or dd_parsed.fragment):
            console.print("[red]--defectdojo-url должен быть абсолютным HTTPS URL[/red]")
            raise typer.Exit(2)

    if nmap_enabled and not active:
        console.print("[red]Для --nmap обязателен флаг --active[/red]")
        raise typer.Exit(2)
    if tls_deep_enabled and not active:
        console.print("[red]Для --tls-deep обязателен флаг --active[/red]")
        raise typer.Exit(2)
    if nuclei_enabled and not active:
        console.print("[red]Для --nuclei обязателен флаг --active[/red]")
        raise typer.Exit(2)
    if deep_subdomains and not active:
        console.print("[red]Для --deep-subdomains обязателен флаг --active[/red]")
        raise typer.Exit(2)
    if sqlmap_enabled and not active:
        console.print("[red]Для --sqlmap обязателен флаг --active[/red]")
        raise typer.Exit(2)
    if dalfox_enabled and not active:
        console.print("[red]Для --dalfox обязателен флаг --active[/red]")
        raise typer.Exit(2)
    if openapi_enabled and not active:
        console.print("[red]Для --openapi обязателен флаг --active[/red]")
        raise typer.Exit(2)
    if graphql_deep_enabled and not active:
        console.print("[red]Для --graphql-deep обязателен флаг --active[/red]")
        raise typer.Exit(2)
    if graphql_load_tests and not graphql_deep_enabled:
        console.print("[red]Для --graphql-load-tests обязателен --graphql-deep[/red]")
        raise typer.Exit(2)
    if graphql_load_tests and (yes or not sys.stdin.isatty()):
        console.print("[red]--graphql-load-tests запрещён в CI/неинтерактивном режиме[/red]")
        raise typer.Exit(2)
    if browser_enabled and not active:
        console.print("[red]Для --browser обязателен флаг --active[/red]")
        raise typer.Exit(2)
    if screenshots and not browser_enabled:
        console.print("[red]Для --screenshots обязателен флаг --browser[/red]")
        raise typer.Exit(2)
    if oast and dalfox_enabled and not interactsh_url:
        console.print("[red]Для OAST в Dalfox укажите --interactsh-url[/red]")
        raise typer.Exit(2)
    if oast and not active:
        console.print("[red]Для --oast обязателен флаг --active[/red]")
        raise typer.Exit(2)
    if oast_write_probes and not oast:
        console.print("[red]Для --oast-write-probes обязателен --oast[/red]")
        raise typer.Exit(2)
    if oast_write_probes and (yes or not sys.stdin.isatty()):
        console.print("[red]--oast-write-probes запрещён в CI/неинтерактивном режиме[/red]")
        raise typer.Exit(2)
    if interactsh_url and not oast:
        console.print("[red]--interactsh-url имеет смысл только вместе с --oast[/red]")
        raise typer.Exit(2)
    if dump_data and not sqlmap_enabled:
        console.print("[red]Для --dump-data обязателен флаг --sqlmap[/red]")
        raise typer.Exit(2)
    if dump_data and (yes or not sys.stdin.isatty()):
        console.print("[red]--dump-data запрещён в CI/неинтерактивном режиме[/red]")
        raise typer.Exit(2)
    if mutate and not deep_subdomains:
        console.print("[red]Для --mutate обязателен флаг --deep-subdomains[/red]")
        raise typer.Exit(2)

    scope_hosts: set[str] = set()
    if scope_file:
        if not scope_file.is_file():
            console.print(f"[red]Файл scope не найден: {scope_file}[/red]")
            raise typer.Exit(2)
        scope_hosts = {
            line.strip().lower() for line in scope_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        normalized_target = target if "://" in target else "https://" + target
        target_host = urlparse(normalized_target).hostname or ""
        if not scope_hosts or not host_in_scope(target_host, scope_hosts):
            console.print("[red]Цель не входит в --scope-file (или allowlist пуст). Сканирование отменено.[/red]")
            raise typer.Exit(2)

    if yes:
        if not own:
            console.print(
                "[red]Для --yes обязателен флаг --i-own-this-target "
                "(подтверждение полномочий).[/red]"
            )
            raise typer.Exit(2)
        auth = Authorization(
            target=target.replace("https://", "").replace("http://", "").split("/")[0],
            owner_or_authorized=True,
            allow_intrusive=active,
            allow_stress=stress,
            allow_local_arp=arp,
            operator="cli (флаг --yes)",
            purpose="автоматический запуск",
        )
    else:
        auth = interactive_gate(
            target=target,
            want_intrusive=active,
            want_stress=stress,
            want_arp=arp,
        )

    dump_data_confirmed = False
    if dump_data:
        answer = input("Type YES to dump data: ")
        if answer != "YES":
            console.print("[yellow]SQLMap --dump отменён пользователем.[/yellow]")
            raise typer.Exit(2)
        dump_data_confirmed = True
    graphql_load_tests_confirmed = False
    if graphql_load_tests:
        answer = input("Type GRAPHQL LOAD TESTS: ")
        if answer != "GRAPHQL LOAD TESTS":
            console.print("[yellow]GraphQL batch test отменён пользователем.[/yellow]")
            raise typer.Exit(2)
        graphql_load_tests_confirmed = True
    oast_write_confirmed = False
    if oast_write_probes:
        answer = input("Type OAST POST PROBES: ")
        if answer != "OAST POST PROBES":
            console.print("[yellow]OAST POST probes отменены пользователем.[/yellow]")
            raise typer.Exit(2)
        oast_write_confirmed = True

    case_dir = out / auth.target
    case_dir.mkdir(parents=True, exist_ok=True)
    # Журнал авторизации
    (case_dir / "авторизация.txt").write_text(
        "\n".join(f"{k}: {v}" for k, v in auth.summary().items()),
        encoding="utf-8",
    )

    mods = set(m.strip() for m in modules.split(",")) if modules else None
    config = {
        "crawl_max": crawl_max, "crawl_depth": crawl_depth, "aggressive": aggressive,
        "request_headers": list(header), "cookie": cookie, "scope_hosts": sorted(scope_hosts),
        "login_url": login_url or "", "login_creds": login_creds or "", "account_b": account_b or "",
        "deep_subdomains": deep_subdomains, "mutate": mutate, "subdomain_max": subdomain_max,
        "save_sourcemaps": save_sourcemaps,
        "sqlmap_enabled": sqlmap_enabled, "dump_data": dump_data,
        "dump_data_confirmed": dump_data_confirmed, "sqlmap_timeout": sqlmap_timeout,
        "sqlmap_extra": sqlmap_extra or "",
        "dalfox_enabled": dalfox_enabled, "dalfox_timeout": dalfox_timeout,
        "browser_enabled": browser_enabled, "screenshots": screenshots,
        "openapi_enabled": openapi_enabled, "nmap_enabled": nmap_enabled,
        "nmap_timeout": nmap_timeout, "tls_deep_enabled": tls_deep_enabled,
        "graphql_deep_enabled": graphql_deep_enabled, "graphql_load_tests": graphql_load_tests,
        "graphql_load_tests_confirmed": graphql_load_tests_confirmed,
        "oast": oast, "oast_enabled": oast, "oast_write_probes": oast_write_probes,
        "oast_write_confirmed": oast_write_confirmed, "interactsh_url": interactsh_url or "",
        "enrich_enabled": enrich_enabled,
        "sarif_enabled": sarif_enabled, "diff_from": str(diff_from) if diff_from else "",
        "defectdojo_url": defectdojo_url or "", "defectdojo_key": defectdojo_key or "",
        "defectdojo_engagement_id": defectdojo_engagement_id or 0,
        "nuclei_enabled": nuclei_enabled, "nuclei_tags": nuclei_tags or "",
        "nuclei_exclude_tags": nuclei_exclude_tags or "",
        "nuclei_templates": nuclei_templates or "", "nuclei_timeout": nuclei_timeout,
        "no_external": no_external, "rate_limit": rate_limit, "proxy": proxy,
    }

    asyncio.run(run_scan(
        target=target, auth=auth, case_dir=case_dir,
        modules_filter=mods, config=config,
        timeout=timeout, verify_tls=not no_verify, proxy=proxy,
    ))


@app.command("wizard")
def wizard_cmd():
    """Интерактивный мастер: вопросы простыми словами для обывателя."""
    wizard()


def wizard():
    """Дружелюбный пошаговый мастер."""
    console.print(Panel(WELCOME, border_style="magenta"))

    # 1. Цель
    target = Prompt.ask(
        "\n[bold]Шаг 1.[/bold] Какой сайт проверяем? (например: [cyan]example.com[/cyan])"
    ).strip()
    if not target:
        console.print("[red]Адрес обязателен. Выход.[/red]")
        raise typer.Exit(1)

    # 2. Глубина
    console.print("\n[bold]Шаг 2.[/bold] Насколько глубоко проверять?")
    console.print("  [cyan]1[/cyan] · Только осмотр снаружи — безопасно, ничего не трогаем")
    console.print("       [dim](заголовки, сертификат, открытые порты, DNS, видимые файлы)[/dim]")
    console.print("  [cyan]2[/cyan] · Полный аудит — попробуем найти уязвимости")
    console.print("       [dim](плюс: подбор путей, проверка форм на SQLi/XSS/LFI/SSRF)[/dim]")
    console.print("  [cyan]3[/cyan] · Полный + стресс-тест")
    console.print("       [bold red](опасно: может уронить сайт, нужны явные права)[/bold red]")
    mode = Prompt.ask("Ваш выбор", choices=["1", "2", "3"], default="1")
    active = mode in ("2", "3")
    stress = mode == "3"

    # 3. Авторизация
    console.print("\n[bold]Шаг 3.[/bold] Юридическая проверка")
    auth = interactive_gate(
        target=target, want_intrusive=active, want_stress=stress, want_arp=False,
    )

    # 4. Выходной каталог
    out_dir = Prompt.ask(
        "\n[bold]Шаг 4.[/bold] Куда сохранить отчёт?",
        default=str(_default_report_dir()),
    )
    case_dir = Path(out_dir) / auth.target
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "авторизация.txt").write_text(
        "\n".join(f"{k}: {v}" for k, v in auth.summary().items()),
        encoding="utf-8",
    )

    console.print(f"\n[green]Готово, начинаем![/green] Отчёт будет здесь: {case_dir}/\n")

    asyncio.run(run_scan(
        target=target, auth=auth, case_dir=case_dir,
        modules_filter=None,
        config={"crawl_max": 80, "crawl_depth": 3},
        timeout=10.0, verify_tls=True, proxy=None,
    ))

    console.print("\n[bold green]Готово![/bold green] Откройте [cyan]report.html[/cyan] "
                  "в браузере — там понятные пояснения по каждой находке.")


@app.command("list-modules")
def list_modules_cmd():
    """Показать установленные модули и требования к разрешению."""
    table = Table(title="Модули MortyScan v20")
    table.add_column("Модуль", style="cyan")
    table.add_column("Режим")
    table.add_column("Описание")
    for name, module, description in ALL_MODULES:
        if name == "auth":
            mode = "только с --login-url / credentials"
        elif name == "nuclei":
            mode = "--active + --nuclei"
        elif name == "subdomain_deep":
            mode = "пассивный; deep: --active + --deep-subdomains"
        elif name == "sqlmap":
            mode = "--active + --sqlmap"
        elif name == "dalfox":
            mode = "--active + --dalfox"
        elif name == "browser":
            mode = "--active + --browser"
        elif name == "openapi":
            mode = "--active + --openapi"
        elif name == "graphql_deep":
            mode = "--active + --graphql-deep"
        elif getattr(module, "REQUIRES_STRESS", False):
            mode = "двойное разрешение"
        elif getattr(module, "REQUIRES_INTRUSIVE", False):
            mode = "--active"
        else:
            mode = "пассивный"
        table.add_row(name, mode, description)
    console.print(table)


@app.command("version")
def version_cmd():
    """Показать версию."""
    console.print(f"MortyScan v{__version__} «{__codename__}»")


def main():
    app()


if __name__ == "__main__":
    main()
