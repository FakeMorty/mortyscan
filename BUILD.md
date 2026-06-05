# Сборка MortyScan (.exe / standalone бинарник + установщик)

## 🔥 Самый простой способ — GitHub Actions (рекомендуется)

Запушьте репозиторий на GitHub и создайте тег — GitHub автоматически соберёт **Windows .exe** и **установщик**:

```bash
git add .
git commit -m "Add PyInstaller + Inno Setup build"
git tag v17.0.0
git push origin v17.0.0
```

Через 3–5 минут в разделе **Releases** появятся:
- `MortyScan.exe` — portable, запускается сразу
- `MortyScan-Setup.exe` — установщик с ярлыками и PATH

### Ручной запуск workflow
Если не хотите создавать тег: **Actions → Build MortyScan Windows Installer → Run workflow**.

---

## 🖥 Локальная сборка на Windows

### Требования
- Windows 10/11
- [Python 3.12](https://www.python.org/downloads/)
- [Inno Setup 6](https://jrsoftware.org/isinfo.php)

### One-click сборка
```cmd
build.bat
```

### Ручная сборка
```powershell
# 1. Установить зависимости
pip install -r requirements.txt
pip install pyinstaller

# 2. Собрать .exe
pyinstaller mortyscan.spec --clean --noconfirm

# 3. Собрать установщик
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss
```

**Результат:**
- `dist\MortyScan.exe` — portable
- `Output\MortyScan-Setup.exe` — установщик

### Использование собранного .exe
```cmd
MortyScan.exe version
MortyScan.exe scan example.com --active --yes --i-own-this-target
```

---

## 🐧 Сборка в Linux / macOS (бинарник для текущей ОС)

> ⚠️ PyInstaller **не умеет** собирать Windows .exe из Linux. Для `.exe` используйте GitHub Actions или Windows.

```bash
pip install -r requirements.txt
pip install pyinstaller
pyinstaller mortyscan.spec --clean --noconfirm
# Результат: dist/MortyScan (ELF/Mach-O бинарник)
```

Проверка:
```bash
./dist/MortyScan version
```

---

## 📁 Файлы сборки

| Файл | Назначение |
|------|------------|
| `mortyscan.spec` | PyInstaller: entry point, hidden imports, data files |
| `entry_point.py` | Обёртка для PyInstaller (импортирует `mortyscan.cli`) |
| `installer.iss` | Inno Setup: окна установки, ярлыки, PATH, русский язык |
| `build.bat` | One-click сборка на Windows |
| `.github/workflows/build.yml` | GitHub Actions pipeline (Windows runner + Inno Setup) |

---

## 🚀 Загрузка на GitHub Releases

Workflow автоматически создаёт Release и прикрепляет артефакты. Если нужно вручную:

```bash
gh release create v17.0.0 dist/MortyScan.exe Output/MortyScan-Setup.exe \
  --title "MortyScan v17.0.0" --notes "Windows portable + installer"
```

Или через веб-интерфейс: **Releases → Draft a new release → Attach binaries**.
