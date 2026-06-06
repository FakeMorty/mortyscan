@echo off
:: Сборка MortyScan 18 portable .exe на Windows
:: Требует: Python 3.10+, pip

echo [1/3] Installing Python dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

echo [2/3] Building standalone .exe with PyInstaller...
pyinstaller mortyscan.spec --clean --noconfirm

echo [3/3] Done!
echo   - Portable .exe: dist\MortyScan.exe
echo.
echo To build GitHub Releases bootstrap Setup.exe, use installer_online.iss
pause
