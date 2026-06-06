# Сборка MortyScan 18.2 (.exe only, без Setup)

## 🔥 Самый простой способ — GitHub Actions (рекомендуется)

Запушьте репозиторий на GitHub и создайте тег — GitHub автоматически соберёт:

- `MortyScan.exe` — portable Windows-бинарник

```bash
git add .
git commit -m "Prepare MortyScan 18.2 release"
git tag v18.2.0
git push origin v18.2.0
```

Через 3–5 минут в разделе **Releases** появится:
- `MortyScan.exe`

### Ручной запуск workflow
Если не хотите создавать тег: **Actions → Build MortyScan Windows Portable Release → Run workflow**.

---

## 🖥 Что именно происходит в workflow

Pipeline делает следующее:
1. ставит Python и зависимости
2. собирает `MortyScan.exe` через PyInstaller
3. публикует его в **GitHub Releases**

Никаких установщиков больше не собирается — MortyScan теперь распространяется как portable `.exe`.

---

## 🖥 Локальная сборка portable .exe на Windows

### Требования
- Windows 10/11
- [Python 3.12](https://www.python.org/downloads/)

### One-click portable сборка
```cmd
build.bat
```

### Ручная сборка portable .exe
```powershell
pip install -r requirements.txt
pip install pyinstaller
pyinstaller mortyscan.spec --clean --noconfirm
```

**Результат:**
- `dist\MortyScan.exe`

### Использование собранного .exe
```cmd
MortyScan.exe version
MortyScan.exe scan example.com --active --yes --i-own-this-target
MortyScan.exe update --yes
```

---

## 🐧 Сборка в Linux / macOS

> ⚠️ PyInstaller **не умеет** собирать Windows `.exe` из Linux/macOS.
> Для Windows-артефактов используйте GitHub Actions или Windows.

```bash
pip install -r requirements.txt
pip install pyinstaller
pyinstaller mortyscan.spec --clean --noconfirm
```

---

## 📁 Файлы сборки

| Файл | Назначение |
|------|------------|
| `mortyscan.spec` | PyInstaller: сборка `MortyScan.exe` |
| `entry_point.py` | Точка входа для PyInstaller |
| `build.bat` | Локальная сборка portable `.exe` |
| `.github/workflows/build.yml` | GitHub Actions: build + release upload |

---

## 🚀 Публикация вручную через GitHub CLI

```bash
gh release create v18.2.0 dist/MortyScan.exe \
  --title "MortyScan v18.2.0" --notes "Windows portable release"
```
