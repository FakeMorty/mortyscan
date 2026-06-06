# Сборка MortyScan 18.1 (.exe + GitHub Releases Setup.exe)

## 🔥 Самый простой способ — GitHub Actions (рекомендуется)

Запушьте репозиторий на GitHub и создайте тег — GitHub автоматически соберёт:

- `MortyScan.exe` — portable Windows-бинарник
- `Setup.exe` — bootstrap/online installer, который скачивает `MortyScan.exe` из GitHub Releases и устанавливает его

```bash
git add .
git commit -m "Prepare MortyScan 18 release"
git tag v18.1.0
git push origin v18.1.0
```

Через 3–5 минут в разделе **Releases** появятся:
- `MortyScan.exe`
- `Setup.exe`

### Ручной запуск workflow
Если не хотите создавать тег: **Actions → Build MortyScan Windows Release → Run workflow**.

---

## 🖥 Что именно происходит в workflow

Pipeline делает следующее:
1. ставит Python и зависимости
2. собирает `MortyScan.exe` через PyInstaller
3. собирает `Setup.exe` через Inno Setup (`installer_online.iss`)
4. публикует оба файла в **GitHub Releases**

`Setup.exe` знает:
- owner репозитория
- имя репозитория
- tag релиза

и при установке скачивает именно тот `MortyScan.exe`, который лежит в этом release.

---

## 🖥 Локальная сборка portable .exe на Windows

### Требования
- Windows 10/11
- [Python 3.12](https://www.python.org/downloads/)
- [Inno Setup 6](https://jrsoftware.org/isinfo.php) — только если хотите собрать `Setup.exe`

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

---

## 🧩 Локальная сборка online Setup.exe

Если хотите локально собрать тот же bootstrap installer, что публикуется в Releases:

```powershell
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" `
  "/DMyAppVersion=18.1.0" `
  "/DMyReleaseTag=v18.1.0" `
  "/DMyRepoOwner=FakeMorty" `
  "/DMyRepoName=mortyscan" `
  "/DMyPortableAssetName=MortyScan.exe" `
  installer_online.iss
```

**Результат:**
- `Output\Setup.exe`

> Важно: такой `Setup.exe` рассчитан на то, что в указанном release уже лежит `MortyScan.exe`.

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
| `installer.iss` | Обычный offline-установщик (локальная упаковка) |
| `installer_online.iss` | Bootstrap `Setup.exe`, который скачивает `MortyScan.exe` из Releases |
| `build.bat` | Локальная сборка portable `.exe` |
| `.github/workflows/build.yml` | GitHub Actions: build + release upload |

---

## 🚀 Публикация вручную через GitHub CLI

```bash
gh release create v18.1.0 dist/MortyScan.exe Output/Setup.exe \
  --title "MortyScan v18.1.1.0" --notes "Windows portable + bootstrap installer"
```
