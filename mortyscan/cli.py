"""Командная строка MortyScan v18.1 «Инквизитор».

Примеры:
  python -m mortyscan                                         # интерактивный мастер
  python -m mortyscan scan example.com                        # пассивный аудит
  python -m mortyscan scan example.com --active               # + активные проверки
  python -m mortyscan scan a.com,b.com --active --yes --i-own-this-target
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from . import __codename__, __version__
from .ethics import Authorization, interactive_gate
from .runner import run_scan
from .updater import maybe_offer_update


def _default_report_dir() -> Path:
    """Путь к папке отчётов по умолчанию.
    В Termux → ~/storage/downloads/MortyScan (видно в Android).
    В обычной системе → ~/MortyScanReports.
    """
    home = Path.home()
    if os.environ.get("TERMUX_VERSION") or (home / "storage" / "downloads").exists():
        d = home / "storage" / "downloads" / "MortyScan"
        d.mkdir(parents=True, exist_ok=True)
        return d
    d = home / "MortyScanReports"
    d.mkdir(parents=True, exist_ok=True)
    return d


app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    invoke_without_command=True,
    pretty_exceptions_enable=False,
    help=f"MortyScan v{__version__} «{__codename__}» — сканер безопасности сайтов "
         f"для авторизованного тестирования.",
)
console = Console()

ASCII_LOGO = r"""
███╗   ███╗ ██████╗ ██████╗ ████████╗██╗   ██╗
████╗ ████║██╔═══██╗██╔══██╗╚══██╔══╝╚██╗ ██╔╝
██╔████╔██║██║   ██║██████╔╝   ██║    ╚████╔╝
██║╚██╔╝██║██║   ██║██╔══██╗   ██║     ╚██╔╝
██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║      ██║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝      ╚═╝
"""

WELCOME = f"""[bold magenta]{ASCII_LOGO}[/bold magenta]
[bold white]MortyScan v{__version__} «{__codename__}»[/bold white]
[dim]Русскоязычный аудитор безопасности сайтов[/dim]

[yellow]Что умею:[/yellow]
  • Проверять DNS, сертификат, заголовки, HTTP-методы и порты
  • Собирать сведения о сайте: IP, ASN, страна, регистратор, редиректы, CDN/WAF
  • Искать забытые файлы (.env, бэкапы, .git, source maps, Swagger/OpenAPI)
  • Тестировать SQLi, XSS, SSTI, LFI, SSRF, открытые редиректы
  • Поддерживать несколько целей сразу — через запятую
  • После сканирования автоматически открывать папку с результатами
  • Работать в цикле без закрытия мастера после одной проверки
"""


def _split_targets(raw: str) -> list[str]:
    parts = raw.replace(";", ",").replace("\n", ",").split(",")
    seen: set[str] = set()
    out: list[str] = []
    for part in parts:
        target = part.strip()
        if not target:
            continue
        if target not in seen:
            seen.add(target)
            out.append(target)
    return out


def _case_name(target: str) -> str:
    raw = target.strip()
    normalized = raw if "://" in raw else f"https://{raw}"
    p = urlparse(normalized)
    host = p.hostname or raw
    return host + (f":{p.port}" if p.port else "")


def _write_auth_log(case_dir: Path, auth: Authorization, target: str) -> None:
    payload = auth.summary()
    payload["цель"] = target
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "авторизация.txt").write_text(
        "\n".join(f"{k}: {v}" for k, v in payload.items()),
        encoding="utf-8",
    )


def _open_path(path: Path) -> None:
    if os.environ.get("CI"):
        return
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:
        console.print(f"[yellow]Не удалось автоматически открыть:[/yellow] {path}")


def _auth_target_label(targets: list[str]) -> str:
    if len(targets) == 1:
        return targets[0]
    if len(targets) <= 3:
        return ", ".join(targets)
    return f"{len(targets)} целей"


def _run_targets(
    *,
    targets: list[str],
    auth: Authorization,
    out: Path,
    modules: Optional[set[str]],
    config: dict,
    timeout: float,
    verify_tls: bool,
    proxy: Optional[str],
    open_report_dir: bool,
) -> list[Path]:
    case_dirs: list[Path] = []
    for idx, target in enumerate(targets, start=1):
        case_dir = out / _case_name(target)
        _write_auth_log(case_dir, auth, target)
        case_dirs.append(case_dir)
        if len(targets) > 1:
            console.print()
            console.rule(f"[bold cyan]Цель {idx}/{len(targets)} → {target}")
        asyncio.run(
            run_scan(
                target=target,
                auth=auth,
                case_dir=case_dir,
                modules_filter=modules,
                config=config,
                timeout=timeout,
                verify_tls=verify_tls,
                proxy=proxy,
            )
        )

    if open_report_dir and case_dirs:
        path_to_open = out if len(case_dirs) > 1 else case_dirs[0]
        console.print(f"\n[green]Открываю папку с результатами:[/green] {path_to_open}")
        _open_path(path_to_open)
    return case_dirs


@app.callback()
def _main(ctx: typer.Context):
    """Если запустили без подкоманды — открыть мастер."""
    if ctx.invoked_subcommand is None:
        wizard()


@app.command("scan")
def scan_cmd(
    target: str = typer.Argument(..., help="Домен/URL. Можно несколько через запятую."),
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
        help="Список модулей через запятую (recon,siteinfo,headers,methods,tls,tech,ports,crawler,"
             "graphql,discovery,vulns,jwt,takeover,local_arp,stress).",
    ),
    timeout: float = typer.Option(10.0, "--timeout", help="Таймаут на HTTP-запрос, сек."),
    no_verify: bool = typer.Option(False, "--no-verify",
                                   help="Не проверять сертификат TLS (для самоподписных)."),
    proxy: Optional[str] = typer.Option(None, "--proxy",
                                        help="HTTP-прокси, напр. http://127.0.0.1:8080 (Burp)."),
    crawl_max: int = typer.Option(80, "--crawl-max", help="Лимит страниц для краулера."),
    crawl_depth: int = typer.Option(3, "--crawl-depth", help="Глубина краула."),
    aggressive: bool = typer.Option(False, "--aggressive",
                                    help="Более глубокий, но всё ещё проверочный режим: шире wordlist, "
                                         "дополнительные payload'ы, аудит HTTP-методов/TRACE."),
    open_report_dir: bool = typer.Option(True, "--open-report-dir/--no-open-report-dir",
                                         help="Автоматически открыть папку с результатами после скана."),
    check_updates: bool = typer.Option(True, "--check-updates/--no-check-updates",
                                       help="Проверять наличие новой версии перед запуском."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Запустить сканирование."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    targets = _split_targets(target)
    if not targets:
        console.print("[red]Не указана ни одна цель.[/red]")
        raise typer.Exit(1)

    if check_updates and maybe_offer_update(interactive=not yes):
        raise typer.Exit(0)

    if stress and not own:
        console.print("[red]Для --stress обязателен флаг --i-own-this-target[/red]")
        raise typer.Exit(2)

    auth_label = _auth_target_label(targets)
    if yes:
        if not own:
            console.print(
                "[red]Для --yes обязателен флаг --i-own-this-target "
                "(подтверждение полномочий).[/red]"
            )
            raise typer.Exit(2)
        auth = Authorization(
            target=auth_label,
            owner_or_authorized=True,
            allow_intrusive=active,
            allow_stress=stress,
            allow_local_arp=arp,
            operator="cli (флаг --yes)",
            purpose="автоматический запуск",
        )
    else:
        auth = interactive_gate(
            target=auth_label,
            want_intrusive=active,
            want_stress=stress,
            want_arp=arp,
        )

    mods = {m.strip() for m in modules.split(",") if m.strip()} if modules else None
    config = {"crawl_max": crawl_max, "crawl_depth": crawl_depth, "aggressive": aggressive}
    _run_targets(
        targets=targets,
        auth=auth,
        out=out,
        modules=mods,
        config=config,
        timeout=timeout,
        verify_tls=not no_verify,
        proxy=proxy,
        open_report_dir=open_report_dir,
    )


@app.command("wizard")
def wizard_cmd():
    """Интерактивный мастер: вопросы простыми словами для обывателя."""
    wizard()


def wizard():
    """Дружелюбный пошаговый мастер, который не закрывается после одной проверки."""
    console.print(Panel(WELCOME, border_style="magenta", expand=False, padding=(1, 2)))
    if maybe_offer_update(interactive=True):
        return

    while True:
        target_raw = Prompt.ask(
            "\n[bold]Шаг 1.[/bold] Какой сайт проверяем? Можно несколько через запятую"
            " (например: [cyan]example.com, api.example.com[/cyan])"
        ).strip()
        targets = _split_targets(target_raw)
        if not targets:
            console.print("[red]Нужна хотя бы одна цель. Выход.[/red]")
            raise typer.Exit(1)

        console.print("\n[bold]Шаг 2.[/bold] Насколько глубоко проверять?")
        console.print("  [cyan]1[/cyan] · Только осмотр снаружи — безопасно, ничего не трогаем")
        console.print("       [dim](заголовки, сертификат, открытые порты, DNS, видимые файлы)[/dim]")
        console.print("  [cyan]2[/cyan] · Полный аудит — попробуем найти уязвимости")
        console.print("       [dim](плюс: подбор путей, проверка форм на SQLi/XSS/LFI/SSRF)[/dim]")
        console.print("  [cyan]3[/cyan] · Полный + стресс-тест")
        console.print("       [bold red](опасно: может замедлить или уронить сайт, нужны явные права)[/bold red]")
        mode = Prompt.ask("Ваш выбор", choices=["1", "2", "3"], default="1")
        active = mode in ("2", "3")
        stress = mode == "3"
        aggressive = Confirm.ask(
            "Включить [yellow]режим поглубже[/yellow] (больше путей, больше эвристик, шире аудит методов)?",
            default=False,
        )

        console.print("\n[bold]Шаг 3.[/bold] Юридическая проверка")
        auth = interactive_gate(
            target=_auth_target_label(targets),
            want_intrusive=active,
            want_stress=stress,
            want_arp=False,
        )

        out_dir = Prompt.ask(
            "\n[bold]Шаг 4.[/bold] Куда сохранить отчёт?",
            default=str(_default_report_dir()),
        )
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)

        console.print(f"\n[green]Готово, начинаем![/green] Результаты будут здесь: {out}/\n")
        _run_targets(
            targets=targets,
            auth=auth,
            out=out,
            modules=None,
            config={"crawl_max": 80, "crawl_depth": 3, "aggressive": aggressive},
            timeout=10.0,
            verify_tls=True,
            proxy=None,
            open_report_dir=True,
        )
        console.print("\n[bold green]Готово![/bold green] HTML-отчёт и JSON уже сохранены, папка с результатами открыта.")
        if not Confirm.ask("\nПроверить ещё одну цель или список целей?", default=True):
            console.print("[bold magenta]Спасибо, что используете MortyScan.[/bold magenta]")
            break


@app.command("version")
def version_cmd():
    """Показать версию."""
    console.print(f"MortyScan v{__version__} «{__codename__}»")


def main():
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Остановлено пользователем.[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        console.print(Panel(
            f"[bold red]Что-то пошло не так.[/bold red]\n\n{e}\n\n"
            "Traceback скрыт, чтобы не пугать пользователя. Если проблема повторяется — "
            "запустите с флагом [cyan]-v[/cyan] и покажите лог разработчику.",
            title=f"MortyScan v{__version__}",
            border_style="red",
        ))
        raise typer.Exit(1)


if __name__ == "__main__":
    main()
