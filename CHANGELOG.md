# Changelog

## v20.4 «OAST, Nmap и TLS deep» (реализовано с безопасными ограничениями)

- Добавлен отдельный opt-in `oast` через ProjectDiscovery `interactsh-client`: максимум 12 in-scope GET probes, уникальные корреляции, 5-секундный polling до 60 секунд, временные файлы и безопасное завершение managed process group. Режим по умолчанию только GET; до двух XML/webhook POST probes требуют дополнительный `--oast-write-probes` и отдельный TTY-подтверждённый ввод, RCE payloads не отправляются.
- Базовый TCP connect scan теперь требует `--active`; явный `--nmap` дополнительно ограничен портами, retry/rate/timeout, proxy/scope/no-external gates и bounded XML parser, findings не сохраняют сырые NSE output.
- Добавлен optional `.[tls]` extra и `--tls-deep` SSLyze аудит протоколов/шифров, Heartbleed, ROBOT, сертификата и HSTS с graceful skip, HTTPS/scope/no-external gates.
- Async tool wrapper теперь ограничивает время drain stdout/stderr и завершает process group даже если потомок пережил родительский процесс.
- Добавлены unit-тесты OAST correlation/scope, Nmap XML/guard, TLS finding mapping/optional skip и subprocess descendant cleanup.

## v20.3 «Экспорт и сравнение»

- Добавлен SARIF 2.1.0 export с `ruleId=finding.type`, severity mapping и SHA-256 evidence fingerprints.
- Добавлены report diff по `(type, target, evidence-hash)` со статусами `new`, `fixed`, `still_open`, `regressed`.
- Добавлен явно включаемый HTTPS DefectDojo import-scan; API key передаётся только в Authorization header и никогда не попадает в отчёт/логи.
- JSON отчёта получил стабильный `schema_version: "2.0"`, diff отображается отдельным разделом в JSON/HTML/PDF.
- Добавлены тесты SARIF redaction, всех четырёх diff-состояний, DefectDojo multipart и блокировки upload через `--no-external`.

## v20.2 «Attack Path Correlation»

- Добавлен `chain`: 10 YAML-правил корреляции attack paths; finding включает ID компонентов, модуль не делает сетевых запросов.

## v20.1 «CVE enrichment»

- Добавлен opt-in `--enrich`: пакетные EPSS, CISA KEV-кэш на 24 часа и ограниченные OSV lookups для pinned versions из уже обнаруженных in-scope manifests.
- Обогащение запрашивает только CVE IDs и package coordinates; target URL, credentials и HTTP bodies не отправляются. `--no-external` отключает запросы.
- JSON/HTML/PDF выдача упорядочивается по KEV, затем EPSS и CVSS; API результаты и cache имеют строгие лимиты.
- Добавлены mocked-тесты EPSS/KEV/OSV и attack-chain корреляции, описания модулей.

## 19.2.0 — v19.2 «Эксплуатация с предохранителями»

- Добавлены SQLMap, Dalfox и optional Playwright-интеграции за явными CLI-флагами; SQLMap запускается только на SQLi-кандидатах `vulns`.
- SQLMap safe/aggressive не делают dump; `--dump-data` требует TTY и точный ввод `YES`, запрещён в CI, с blacklist destructive-like URL и timeout максимум 180 секунд.
- Добавлен read-only JS/source-map анализ с endpoint mining, secret/JWT pattern detection, SHA-256 evidence и лимитированным opt-in сохранением исходников.
- Добавлена пассивная Subfinder-энумерация и opt-in глубокий DNS brute-force/Amass/mutations, wildcard DNS filtering, scope guard и takeover inventory.
- Добавлены query-redaction в URL отчётов, optional browser screenshot previews, внешние инструменты используют общий async subprocess wrapper.
- Включён optional packaging extra: `pip install -e .[browser]`.
- Добавлены mocked tests для SQLMap, Dalfox, Playwright fallback, source maps, subdomain enumeration и report redaction.

## 19.1.0 — v19.1 «Быстрые победы»

- Добавлены пассивный WAF/CDN fingerprint и активные модули `exposures`, `redirect`, расширенный `cors_audit`.
- Добавлена явная интеграция Nuclei через async subprocess wrapper. Запуск требует `--active --nuclei`; встроенные шаблоны OAST, default-login, brute-force, fuzz и DoS исключаются.
- Добавлены rate limit, soft-404 и проверка содержимого ответов для поиска exposures.
- Поддержаны `--cookie`, повторяемые `--header`, `--scope-file`, `--no-external` и настройки Nuclei; учётные заголовки не уходят на другой origin.
- Совместимо расширена модель Finding полями `id`, `type`, `tags`; ScanContext сохраняет fingerprint WAF.
- Добавлена команда `--list-modules`.
- Добавлены unit-тесты subprocess wrapper и новых HTTP-модулей.
