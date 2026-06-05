# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec для MortyScan — сборка в один .exe / бинарник.

Использование (из корня проекта, где лежит папка mortyscan/ и README.md):
    pip install pyinstaller
    pyinstaller mortyscan.spec --clean --noconfirm
"""
from PyInstaller.building.build_main import Analysis, PYZ, EXE
from pathlib import Path

# Корень проекта = текущая директория при запуске pyinstaller
ROOT = Path('.').resolve()
# Python-пакет лежит внутри: ROOT/mortyscan/
PKG = ROOT / "mortyscan"

a = Analysis(
    [str(ROOT / "entry_point.py")],
    pathex=[str(ROOT), str(ROOT / "mortyscan")],
    binaries=[],
    datas=[
        (str(PKG / "data" / "wordlist.txt"), "mortyscan/data"),
    ],
    hiddenimports=[
        "typer",
        "typer.main",
        "click",
        "rich",
        "rich.console",
        "rich.panel",
        "rich.prompt",
        "rich.progress",
        "rich.table",
        "rich.text",
        "rich.style",
        "httpx",
        "httpcore",
        "httpcore._backends.sync",
        "httpcore._backends.anyio",
        "anyio",
        "anyio._backends._trio",
        "anyio._backends._asyncio",
        "h2",
        "hpack",
        "hyperframe",
        "certifi",
        "idna",
        "sniffio",
        "scapy",
        "scapy.all",
        "scapy.layers.all",
        "scapy.layers.http",
        "scapy.layers.inet",
        "scapy.layers.l2",
        "scapy.sendrecv",
        "scapy.arch.windows",
        "fpdf",
        "fpdf.fpdf",
        "urllib3",
        "requests",
        "dns",
        "dns.resolver",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "matplotlib",
        "numpy",
        "pandas",
        "tkinter",
        "PyQt5",
        "PyQt6",
        "PySide2",
        "PySide6",
        "wx",
        "PIL",
        "setuptools",
        "pytest",
        "sphinx",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="MortyScan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "icon.ico"),
)
