# Nuclei (внешний инструмент, opt-in)

Установите Nuclei отдельно. MortyScan не устанавливает и не обновляет его автоматически.
Запуск требует явных `--active --nuclei` и авторизованного подтверждения.

```bash
mortyscan scan https://owned.example --active --yes --i-own-this-target --nuclei
```

Встроенная конфигурация ограничена CVE, exposures, misconfiguration и takeover templates; OAST, default-login,
brute-force, fuzz, headless и DoS-теги исключены. Внешний инструмент запускается без shell, с общим таймаутом,
ограниченным захватом stdout/stderr и rate limit. При отсутствии бинарника сканирование продолжается,
а в отчёт записывается `tool_missing: nuclei`. Используйте кастомные шаблоны только после проверки их поведения.

`--no-external` запрещает запуск внешнего бинарника даже при `--nuclei`.
