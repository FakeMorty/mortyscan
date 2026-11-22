# MortyScan v20 «Deep Attack Platform»

> Сканер безопасности веб-сайтов на русском языке для **авторизованного** аудита.
> Объясняет каждую находку простыми словами: что это, чем грозит, как чинить.

[![использование](https://img.shields.io/badge/только-для%20авторизованного-red)]()
[![python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![language](https://img.shields.io/badge/язык-русский-orange)]()

---

## ⚖️ Юридическое предупреждение

MortyScan умеет **активно тестировать** сайты (фуззинг, проверки на SQLi/XSS/LFI/SSRF,
сканирование портов) и проводить **нагрузочный тест** (DoS-подобный).

Запуск этих функций против систем, которыми вы **НЕ владеете** и на тестирование которых
у вас **НЕТ письменного разрешения**, является уголовно наказуемым деянием:
- **РФ** — статьи 272, 273 УК РФ
- **США** — CFAA
- **Великобритания** — Computer Misuse Act 1990
- и аналоги в других юрисдикциях.

Программа отказывается выполнять активные проверки без вашего явного подтверждения
(интерактивно или через флаг `--i-own-this-target`). Используя её, вы принимаете
**полную юридическую и этическую ответственность**.

---

## Что нового в v20

- `--enrich` по явному opt-in добавляет EPSS, CISA KEV и OSV advisory к уже найденным CVE/зависимостям; cache обновляется раз в 24 часа.
- Наружу передаются только CVE IDs и package coordinates, не URLs цели, cookies, headers или response bodies; `--no-external` отключает запросы.
- `chain` сопоставляет findings с 10 YAML attack-path правилами и создаёт `type=attack_chain`; постпроцессор не делает сетевых запросов.
- `--sarif` создаёт SARIF 2.1.0, `--diff-from` добавляет new/fixed/still_open/regressed, а DefectDojo требует явных HTTPS URL, API key и engagement ID.
- Сначала обогащаются CVE из findings и pinned dependencies из найденных in-scope manifests; неподтверждённые диапазоны версий пропускаются.
- Дополнительные opt-in модули v20: Nmap через `--active --nmap`, глубокий TLS через `--active --tls-deep` и ограниченные Interactsh probes через `--active --oast` (POST XXE/webhook дополнительно требует `--oast-write-probes` и ручное подтверждение).

## Что нового в v19.2

- SQLMap запускается только для SQLi-кандидатов `vulns`; безопасный и `--aggressive` режимы не делают dump. `--dump-data` запрещён в CI и требует точного подтверждения `YES` в TTY.
- Добавлены опциональные Dalfox и Playwright; OAST и скриншоты имеют отдельные явные флаги.
- JS/source-map анализ собирает endpoint'ы и хешированные secret evidence; source map сохраняются только по отдельному флагу и с ограничением объёма.
- Subfinder работает как пассивный сбор; активный DNS wordlist/Amass/mutations включаются отдельно, с wildcard DNS-фильтрацией и scope-гейтами.
- Отчёты не сохраняют query-значения URL; Playwright может добавить локальные скриншоты как превью.

## Что нового в v19.1

- Добавлены модули `waf`, `exposures`, `redirect` и явно включаемый `nuclei`.
- Активные модули ограничены rate limit; проверки утечек файлов используют soft-404 и сигнатуры содержимого.
- Nuclei запускается только с `--active --nuclei`; OAST, default-login, brute-force и DoS-теги исключены.
- Добавлена асинхронная обёртка внешних бинарников с timeout, ограничением вывода и graceful skip.
- `Finding` получил совместимые дополнительные поля `id`, `type` и `tags`; добавлена контекстная WAF-метаинформация.
- `--cookie` и повторяемый `--header` привязаны к origin цели; `--scope-file` блокирует HTTP-запросы вне allowlist.

## Что нового в v18 (по сравнению с v17)

| | v17 «Инквизитор» | v18 «Инквизитор» |
|---|---|---|
| Архитектура | один файл, 250 строк | модульный пакет, 13 плагинов |
| Сеть | sync `requests` + 200 threads | async `httpx` + asyncio |
| Локализация | смесь ru/en | **полностью русский интерфейс** |
| Подсказки | нет | для каждой уязвимости — «что это», «аналогия», «чем грозит», «как чинить» |
| Разведка | DNS A | DNS A/AAAA/MX/NS/TXT/SOA/CNAME/CAA + SPF/DMARC + сабдомены через crt.sh |
| Сведения о сайте | нет | IP/IPv6, PTR, ASN, страна/город, регистратор, RDAP, финальный URL, title, HTTP-версия, CDN/WAF |
| Заголовки | server/X-Powered-By | аудит security headers + проверка слабых директив CSP/HSTS + cookies + CORS |
| TLS | нет | проверка версий, срок сертификата, SAN |
| Порты | 6 портов | топ-60 портов async + баннеры + **выделение опасных** (Redis, Mongo, etcd, Docker API) |
| Скрытые пути | 7 путей, тупой 200-чек | 100+ путей с **soft-404 baseline** через сравнение длины и сигнатуры |
| Краулер | нет | async-краулер в scope-доменe, парсит HTML/JS/формы, ищет утечки секретов |
| Уязвимости | error-SQLi + примитивный XSS | SQLi (по ошибке + boolean + time-based), XSS, LFI, SSRF, Open Redirect, SSTI — на параметрах из краула |
| Технологии | нет | фингерпринт + **CVE через NVD API** |
| Захват сабдомена | нет | сравнение CNAME с базой fingerprint'ов «осиротевших» сервисов |
| JWT | нет | разбор alg=none, **брутфорс HS256** по словарю слабых секретов |
| GraphQL | нет | поиск эндпоинтов + проверка интроспекции |
| Стресс-тест | всегда включен | строго opt-in, нужны `--stress` + `--i-own-this-target` |
| Отчёт | PDF (только Windows) | **JSON + HTML + PDF**, на русском, с TL;DR блоком и оглавлением |
| Тесты | нет | автотесты против встроенной уязвимой лабы |

---

## Установка

```bash
git clone https://github.com/FakeMorty/mortyscan.git
cd mortyscan
python3 -m venv .venv && source .venv/bin/activate     # Linux/Mac
# или для Windows:  python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
```

Для установки как Python-пакета с optional extra для SPA-браузера:

```bash
pip install -e '.[browser,api,tls]'
playwright install chromium
```

Playwright и Schemathesis остаются optional extras: без них браузерный модуль пропускается, а OpenAPI использует ограниченный встроенный режим. SQLMap, Dalfox, Subfinder и Amass — отдельные внешние программы; MortyScan запускает их только через ограниченную subprocess-обёртку и сообщает, если бинарника нет.

Требуется Python 3.10+. Старая версия v16 сохранена как `mortyscan_legacy_v16.py`.

---

## Как пользоваться (для обывателей)

### Самый простой способ — мастер

```bash
python -m mortyscan
```

Откроется пошаговый помощник, который задаст 4 вопроса простыми словами:
1. Какой сайт проверяем
2. Насколько глубоко (только осмотр / полный аудит / + стресс-тест)
3. Подтверждение, что вы имеете право это делать
4. Куда сохранить отчёт

### Командная строка

```bash
# Список модулей и отметка, где требуется --active
python -m mortyscan --list-modules

# Пассивный аудит (ничего не ломаем, просто смотрим)
python -m mortyscan scan example.com

# С активными проверками (фуззинг, инъекции) — нужно интерактивное подтверждение
python -m mortyscan scan example.com --active

# Автоматический режим для своих сайтов (без вопросов)
python -m mortyscan scan example.com --active --yes --i-own-this-target

# Более агрессивный, но всё ещё проверочный режим
python -m mortyscan scan example.com --active --aggressive --yes --i-own-this-target

# Авторизованный аудит с cookie и дополнительными заголовками
python -m mortyscan scan https://мой-сайт.example --active --yes --i-own-this-target \\
    --cookie 'session=...' --header 'Authorization: Bearer ...'

# Nuclei включается отдельно; без установленного бинарника сканирование продолжится
python -m mortyscan scan example.com --active --nuclei --yes --i-own-this-target

# Явный Nmap и глубокий TLS аудит (Nmap требует установленный бинарник; SSLyze: pip install '.[tls]')
python -m mortyscan scan example.com --active --nmap --tls-deep --yes --i-own-this-target

# OAST — ограниченные GET probes; клиент/сервер Collaborator получает внешние callbacks
python -m mortyscan scan example.com --active --oast --interactsh-url https://oast.example --yes --i-own-this-target

# Опциональные POST XXE/webhook probes требуют интерактивного ввода подтверждения и могут изменить состояние цели
python -m mortyscan scan example.com --active --oast --oast-write-probes --i-own-this-target

# Пассивный сбор сабдоменов запускается обычно; глубокий DNS-bruteforce — только явно
python -m mortyscan scan example.com --active --deep-subdomains --mutate --yes --i-own-this-target

# Дальнейшая проверка SQLi только для URL с подозрением от vulns; --dump-data потребует ввода YES в терминале
python -m mortyscan scan example.com --active --sqlmap --yes --i-own-this-target

# Отдельный Dalfox/browser запуск; без --aggressive Dalfox пропускает цели с WAF
python -m mortyscan scan example.com --active --dalfox --browser --screenshots --yes --i-own-this-target

# Стресс-тест (опасно! сайт может упасть)
python -m mortyscan scan example.com --active --stress --i-own-this-target

# Выбрать только нужные модули
python -m mortyscan scan example.com --modules crawler,vulns --active --yes --i-own-this-target

# Ограничить все HTTP-запросы явным allowlist scope.txt (по одной записи на строку)
python -m mortyscan scan example.com --active --scope-file scope.txt

# Вход по форме и две изолированные сессии для BOLA-аудита
python -m mortyscan scan example.com --active --login-url https://example.com/login \\
    --login-creds 'alice:...' --account-b 'bob:...' --openapi --i-own-this-target

# SARIF-экспорт и сравнение с предыдущим JSON-отчётом
python -m mortyscan scan example.com --sarif --diff-from cases/example.com/report.json

# Явная отправка SARIF в DefectDojo; API key не сохраняется в отчётах
python -m mortyscan scan example.com --defectdojo-url https://dojo.example \\
    --defectdojo-key "$DD_API_KEY" --defectdojo-engagement-id 123

# Через Burp Suite или другой прокси
python -m mortyscan scan example.com --proxy http://127.0.0.1:8080
```

OpenAPI работает только с read-only GET/HEAD/OPTIONS пробами; POST/PUT/PATCH/DELETE и массовое присваивание не выполняются.

После завершения в каталоге `cases/<сайт>/` будут лежать:
- **`report.html`** — открыть в браузере, самый удобный
- **`report.pdf`** — для печати/отправки начальству
- **`report.json`** — машинно-читаемый, для интеграций
- **`авторизация.txt`** — журнал того, кто и что разрешил

---

## Попробовать безопасно: встроенная уязвимая лаба

В папке `lab/` лежит специально дырявое Flask-приложение для тренировки.

```bash
# Терминал 1: запустить лабу
python lab/vuln_app.py
# Теперь http://127.0.0.1:5055 открыт

# Терминал 2: натравить сканер
python -m mortyscan scan http://127.0.0.1:5055 \
    --active --yes --i-own-this-target --no-verify
```

После запуска вы увидите примерно такой результат:

```
   Серьёзность      Кол-во
 КРИТИЧЕСКАЯ           7
 ВЫСОКАЯ               7
 СРЕДНЯЯ               3
 НИЗКАЯ                9
 ИНФО                  9
 Очки риска          1230
 Вердикт         КАТАСТРОФА
```

Среди находок:
- SQL-инъекции (по ошибке БД) в `/search?q=` и `/user?id=`
- Отражённые XSS в нескольких параметрах и в форме логина
- LFI / Path Traversal в `/file?name=`
- Open Redirect в `/go?url=`
- SSRF в `/fetch?url=`
- Открытый `/.env` с AWS/Stripe-ключами
- CORS отражает любой Origin
- Небезопасные cookie

Откройте `cases/127.0.0.1:5055/report.html` — там по каждой уязвимости есть
блок «Что это / Аналогия / Чем грозит / Как чинить» простыми словами.

---

## Каталог модулей

| Модуль | Активный | Что делает |
|---|:-:|---|
| `auth` | – / `--login-url` | POST-форма входа, проверка cookie/token, отдельная сессия account B; credentials не попадают в отчёт |
| `openapi` | ✓, `--openapi` | Discovery OpenAPI, read-only GET/HEAD/OPTIONS cases, auth-bypass, response status contract, optional BOLA по двум аккаунтам |
| `graphql_deep` | ✓, `--graphql-deep` | Type/field suggestions; batch из 100 aliases — только с отдельным TTY-флагом и подтверждением |
| `enrich` | `--enrich` | EPSS, CISA KEV (24h cache), OSV по найденным pinned dependencies; opt-in, `--no-external` отключает lookups |
| `chain` | – | 10 YAML attack-path корреляций по findings; без сетевых запросов, каждый результат содержит исходные finding IDs |
| `export` | `--sarif`, `--diff-from`, `--defectdojo-*` | SARIF 2.1.0, отчётный diff, явный HTTPS import-scan в DefectDojo |
| `recon` | – | DNS-записи, SPF/DMARC, сабдомены через журналы сертификатов |
| `siteinfo` | – | IP/IPv6, PTR, ASN, страна, регистратор, RDAP, редиректы, HTTP-профиль, CDN/WAF |
| `waf` | – | Пассивный fingerprint WAF/CDN по публичным признакам (эвристика, не гарантия наличия защиты) |
| `headers` | – | HSTS (включая слабый max-age), CSP (unsafe-inline/eval, источники, object-src/base-uri), XFO/XCTO/Referrer-Policy, точный разбор флагов cookie, CORS |
| `methods` | – / ✓ | OPTIONS, TRACE, WebDAV, потенциально опасные HTTP-методы |
| `tls` | – | Версии TLS, срок сертификата, SAN |
| `tls_deep` | ✓, `--tls-deep` | Optional SSLyze protocol/cipher, Heartbleed, ROBOT, certificate/OCSP/HSTS checks |
| `tech` | – | Определение CMS/фреймворков + CVE через NVD |
| `ports` | ✓, `--active`; Nmap: `--nmap` | Async TCP connect scan топ-60 только при `--active`; Nmap service/NSE дополнительно требует явный `--nmap`
| `crawler` | – | Краул сайта, формы, параметры, утечки секретов |
| `subdomain_deep` | – / `--deep-subdomains` | Subfinder по умолчанию; глубокий DNS-bruteforce по SecLists, Amass по флагу, wildcard-фильтр и мутации |
| `js_deep` | – | JS/source maps, API endpoints, secret/JWT pattern mining; evidence хранит только SHA-256, source maps сохраняются только по флагу |
| `browser` | ✓, `--browser` | Optional Playwright SPA/XHR, DOM-XSS диалог, JWT-сбор и opt-in скриншоты |
| `sqlmap` | ✓, `--sqlmap` | Только URL с SQLi-кандидатами из `vulns`; безопасный режим без dump, `--dump-data` требует подтверждения в TTY |
| `dalfox` | ✓, `--dalfox` | XSS reflection и aggressive crawler params; отключён при WAF без `--aggressive` |
| `exposures` | ✓ | До 150 чувствительных путей, сигнатуры тела, soft-404 и rate limit; только GET |
| `redirect` | ✓ | Ограниченные GET-пробы параметров; редиректам не следует |
| `csrf_audit` | – | Анализ POST/PUT/PATCH/DELETE-форм на очевидные CSRF-токены (формы не отправляются) |
| `cors_audit` | ✓ | CORS-пробы на известных endpoint'ах: посторонний Origin, `null`, suffix/subdomain; без изменяющих состояние запросов |
| `nuclei` | ✓, `--nuclei` | Внешние CVE/exposure/misconfiguration шаблоны; отключён по умолчанию, без OAST/default-login/DoS |
| `oast` | ✓, `--oast`; POST: `--oast-write-probes` + TTY confirmation | До 12 in-scope GET probes; отдельный вручную подтверждаемый максимум из 2 XML/JSON POST XXE/webhook probes, без RCE |
| `graphql` | – | Поиск GraphQL + проверка интроспекции |
| `discovery` | ✓ | Подбор скрытых путей с soft-404 baseline |
| `vulns` | ✓ | SQLi (3 типа), XSS, SSTI, LFI, Open Redirect, SSRF |
| `jwt` | – | Разбор JWT, брутфорс HS256 по словарю |
| `takeover` | – | Проверка сабдоменов на возможность захвата |
| `local_arp` | – | ARP-скан ВАШЕЙ локальной сети (нужен root) |
| `stress` | ✓✓ | Нагрузочный тест с ramp-up |

«Активный» — модуль реально отправляет вредоносные пейлоады, может оставить следы в логах,
требует разрешения. «✓✓» — особо опасен, требует двойного подтверждения.

---

## Запуск тестов

```bash
pip install pytest
pytest tests/ -v
```

Тест поднимает уязвимую лабу на случайном порту и убеждается, что сканер
находит все основные классы уязвимостей.

---

## Roadmap v21+

Аутентификация, DefectDojo и diff уже доступны в текущей версии. Идеи за пределами этого ТЗ (например, HTTP request smuggling, race-condition проверки и UI) перечислены в [`docs/roadmap-v21.md`](docs/roadmap-v21.md).

---

## Лицензия и оговорка

Программа выпущена для **обучения и авторизованного тестирования**.
Автор не несёт ответственности за нецелевое использование.

Программа предоставляется «КАК ЕСТЬ», без каких-либо гарантий.
