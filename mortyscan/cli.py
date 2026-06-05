"""Командная строка MortyScan v17 «Инквизитор».

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
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from . import __version__, __codename__
from .ethics import interactive_gate, Authorization
from .runner import run_scan

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


WELCOME = """[bold magenta]MortyScan v17 «Инквизитор»[/bold magenta]
Сканер безопасности веб-сайтов на русском языке.

[yellow]Что я умею:[/yellow]
  • Проверить DNS, сертификат, заголовки, порты
  • Найти забытые файлы (.env, бэкапы, .git)
  • Поймать SQL-инъекции, XSS, LFI, SSRF, открытые редиректы
  • Поискать сабдомены и проверить их на захват
  • Аудитировать JWT-токены
  • Найти GraphQL и проверить, не выдаёт ли он лишнего
  • Сделать стресс-тест (только с явного согласия)
  • Сгенерировать понятный отчёт с пояснениями
"""


@app.callback()
def _main(ctx: typer.Context):
    """Если запустили без подкоманды — открыть мастер."""
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
        help="Список модулей через запятую (recon,headers,tls,tech,ports,crawler,"
             "graphql,discovery,vulns,jwt,takeover,local_arp,stress).",
    ),
    timeout: float = typer.Option(10.0, "--timeout", help="Таймаут на HTTP-запрос, сек."),
    no_verify: bool = typer.Option(False, "--no-verify",
                                   help="Не проверять сертификат TLS (для самоподписных)."),
    proxy: Optional[str] = typer.Option(None, "--proxy",
                                        help="HTTP-прокси, напр. http://127.0.0.1:8080 (Burp)."),
    crawl_max: int = typer.Option(80, "--crawl-max", help="Лимит страниц для краулера."),
    crawl_depth: int = typer.Option(3, "--crawl-depth", help="Глубина краула."),
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

    case_dir = out / auth.target
    case_dir.mkdir(parents=True, exist_ok=True)
    # Журнал авторизации
    (case_dir / "авторизация.txt").write_text(
        "\n".join(f"{k}: {v}" for k, v in auth.summary().items()),
        encoding="utf-8",
    )

    mods = set(m.strip() for m in modules.split(",")) if modules else None
    config = {"crawl_max": crawl_max, "crawl_depth": crawl_depth}

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


@app.command("version")
def version_cmd():
    """Показать версию."""
    console.print(f"MortyScan v{__version__} «{__codename__}»")


def main():
    app()


if __name__ == "__main__":
    main()
