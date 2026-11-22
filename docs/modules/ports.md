# `ports` — TCP ports и Nmap

Базовый TCP connect scan проверяет фиксированный список распространённых портов и запускается только в разрешённом активном режиме (`--active`). Глубокий Nmap scan дополнительно выключен по умолчанию:

```bash
mortyscan scan example.com --active --nmap --nmap-timeout 300 --i-own-this-target
```

Nmap использует `-sT -sV -sC`, ограниченный набор скриптов `vuln,ssl-enum-ciphers,http-enum`, первые 100 портов, `-T3`, retry/scan delay и ограниченный timeout. Он работает только при `--active --nmap`, не запускается при `--no-external`, при proxy (Nmap raw TCP proxy не поддерживает) или вне allowlist scope. Если бинарника нет или XML некорректен, scan продолжится с INFO finding. NSE output ограничен по размеру, CVE вынимаются, сырые script responses в отчёт не сохраняются. Nmap сканирует только целевой адрес и не расширяет список хостов.

`--nmap` создаёт внешний сетевой трафик и логируется на WARNING; запускайте только на разрешённых целях.
