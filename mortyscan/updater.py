"""Проверка обновлений и мягкий self-update через GitHub Releases."""
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
    preferred = ["Setup.exe", "MortyScan.exe"]
    by_name = {a.get("name"): a for a in assets if a.get("name")}
    for name in preferred:
        if name in by_name:
            return by_name[name]
    return assets[0] if assets else None


def _download_file(url: str, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", url, follow_redirects=True, timeout=30) as r:
        r.raise_for_status()
        with out_path.open("wb") as f:
            for chunk in r.iter_bytes():
                if chunk:
                    f.write(chunk)


def _launch_installer(path: Path) -> None:
    if sys.platform.startswith("win"):
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


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
    """Если доступна новая версия и пользователь согласился — скачать/запустить установщик.

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

    should_update = auto_accept or Confirm.ask("Скачать и запустить обновление сейчас?", default=False)
    if not should_update:
        return False

    try:
        asset_name = info["asset_name"] or "Setup.exe"
        tmp_dir = Path(tempfile.gettempdir()) / "mortyscan-update"
        local_path = tmp_dir / asset_name
        console.print(f"[cyan]Скачиваю:[/cyan] {asset_name}")
        _download_file(str(info["asset_url"]), local_path)
        console.print(f"[green]Запускаю обновление:[/green] {local_path}")
        _launch_installer(local_path)
        return True
    except Exception as e:
        console.print(f"[yellow]Не удалось запустить обновление автоматически:[/yellow] {e}")
        if info.get("html_url"):
            console.print(f"[yellow]Скачайте вручную из релиза:[/yellow] {info['html_url']}")
        return False
