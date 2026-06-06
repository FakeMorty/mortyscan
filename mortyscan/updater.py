"""Проверка обновлений и мягкий self-update через GitHub Releases.

Начиная с ветки portable-only, обновление работает без Setup.exe:
скачивается новый MortyScan.exe и подменяет текущий после завершения процесса.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.prompt import Confirm

from . import __version__

console = Console()
REPO_OWNER = "FakeMorty"
REPO_NAME = "mortyscan"
LATEST_RELEASE_API = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"


def _version_tuple(ver: str) -> tuple[int, ...]:
    parts = []
    for p in (ver or "").strip().lstrip("v").split("."):
        if p.isdigit():
            parts.append(int(p))
        else:
            num = "".join(ch for ch in p if ch.isdigit())
            if num:
                parts.append(int(num))
            else:
                parts.append(0)
    return tuple(parts)


def _is_newer(latest: str, current: str) -> bool:
    a = _version_tuple(latest)
    b = _version_tuple(current)
    width = max(len(a), len(b), 3)
    a = a + (0,) * (width - len(a))
    b = b + (0,) * (width - len(b))
    return a > b


def _choose_asset(assets: list[dict[str, Any]]) -> dict[str, Any] | None:
    preferred = ["MortyScan.exe", "MortyScan.zip"]
    by_name = {a.get("name"): a for a in assets if a.get("name")}
    for name in preferred:
        if name in by_name:
            return by_name[name]
    return assets[0] if assets else None


def _download_file(url: str, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", url, follow_redirects=True, timeout=60) as r:
        r.raise_for_status()
        with out_path.open("wb") as f:
            for chunk in r.iter_bytes():
                if chunk:
                    f.write(chunk)


def _open_release_page(url: str) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(url)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", url])
        else:
            subprocess.Popen(["xdg-open", url])
    except Exception:
        console.print(f"[yellow]Не удалось открыть страницу релиза:[/yellow] {url}")


def _is_portable_exe() -> bool:
    return bool(getattr(sys, "frozen", False) and sys.platform.startswith("win") and str(sys.executable).lower().endswith(".exe"))


def _portable_update_script(downloaded_exe: Path, current_exe: Path) -> Path:
    tmp_dir = Path(tempfile.gettempdir()) / "mortyscan-update"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    script = tmp_dir / "apply_update.cmd"
    content = f"""@echo off
setlocal
set "SRC={downloaded_exe}"
set "DST={current_exe}"
:retry
copy /Y "%SRC%" "%DST%" >nul 2>nul
if errorlevel 1 (
  timeout /t 1 /nobreak >nul
  goto retry
)
start "" "%DST%"
del "%SRC%" >nul 2>nul
del "%~f0" >nul 2>nul
"""
    script.write_text(content, encoding="utf-8")
    return script


def _launch_self_replacer(script: Path) -> None:
    if sys.platform.startswith("win"):
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        subprocess.Popen(
            ["cmd.exe", "/c", str(script)],
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
    else:
        subprocess.Popen(["sh", str(script)])


def latest_release_info() -> dict[str, Any] | None:
    if os.environ.get("CI"):
        return None
    try:
        with httpx.Client(timeout=10, follow_redirects=True, headers={"User-Agent": f"MortyScan/{__version__}"}) as client:
            r = client.get(LATEST_RELEASE_API)
            r.raise_for_status()
            data = r.json()
    except Exception:
        return None

    tag = str(data.get("tag_name", "") or "").strip()
    if not tag:
        return None

    version = tag.lstrip("v")
    if not _is_newer(version, __version__):
        return None

    assets = data.get("assets", []) or []
    asset = _choose_asset(assets)
    if not asset:
        return None

    return {
        "tag": tag,
        "version": version,
        "html_url": data.get("html_url", ""),
        "asset_name": asset.get("name", ""),
        "asset_url": asset.get("browser_download_url", ""),
    }


def maybe_offer_update(*, interactive: bool = True, auto_accept: bool = False) -> bool:
    """Если доступна новая версия и пользователь согласился — скачать и применить обновление.

    Возвращает True, если процесс обновления был запущен и текущее приложение должно завершиться.
    """
    info = latest_release_info()
    if not info:
        return False

    console.print(
        f"[bold yellow]Доступно обновление MortyScan {info['version']}[/bold yellow] "
        f"(текущая версия: {__version__})."
    )
    if info.get("html_url"):
        console.print(f"[dim]{info['html_url']}[/dim]")

    if not interactive:
        console.print("[dim]Автообновление пропущено: неинтерактивный режим.[/dim]")
        return False

    should_update = auto_accept or Confirm.ask("Скачать и обновить сейчас?", default=False)
    if not should_update:
        return False

    asset_name = info["asset_name"] or "MortyScan.exe"
    tmp_dir = Path(tempfile.gettempdir()) / "mortyscan-update"
    local_path = tmp_dir / asset_name

    try:
        console.print(f"[cyan]Скачиваю:[/cyan] {asset_name}")
        _download_file(str(info["asset_url"]), local_path)
    except Exception as e:
        console.print(f"[yellow]Не удалось скачать обновление:[/yellow] {e}")
        if info.get("html_url"):
            console.print(f"[yellow]Скачайте вручную из релиза:[/yellow] {info['html_url']}")
        return False

    if _is_portable_exe() and asset_name.lower().endswith(".exe"):
        try:
            current_exe = Path(sys.executable).resolve()
            script = _portable_update_script(local_path.resolve(), current_exe)
            console.print("[green]Обновление готово. Перезапускаю приложение и подменяю исполняемый файл...[/green]")
            _launch_self_replacer(script)
            return True
        except Exception as e:
            console.print(f"[yellow]Автообновление не удалось применить:[/yellow] {e}")

    if info.get("html_url"):
        console.print("[yellow]Автозамена недоступна в этом режиме. Открываю страницу релиза.[/yellow]")
        _open_release_page(str(info["html_url"]))
        return True

    return False
