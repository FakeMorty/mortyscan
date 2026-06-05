@echo off
:: Сборка MortyScan .exe + установщика на Windows (локально)
:: Требует: Python 3.10+, pip, Inno Setup 6

echo [1/4] Installing Python dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

echo [2/4] Building standalone .exe with PyInstaller...
pyinstaller mortyscan.spec --clean --noconfirm

echo [3/4] Building installer with Inno Setup...
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss

echo [4/4] Done!
echo   - Standalone .exe: dist\MortyScan.exe
echo   - Installer:       Output\MortyScan-Setup.exe
pause
