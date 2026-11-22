# `export` — SARIF, DefectDojo и diff

Модуль выполняется после всех сканирующих и постпроцессорных модулей.

## SARIF 2.1.0

```bash
mortyscan scan example.com --sarif
```

Создаёт `report.sarif` в каталоге кейса. `ruleId` соответствует `finding.type`; severity переводится в уровни SARIF. `partialFingerprints` содержит SHA-256 evidence, а URL query/fragment и userinfo не попадают в SARIF.

## Сравнение

```bash
mortyscan scan example.com --diff-from previous/report.json
```

Сравнение использует `(type, target, SHA-256(evidence))` и выдаёт `new`, `fixed`, `still_open`, `regressed`. Регрессия — тот же ключ находки с более высокой severity. Сводка добавляется отдельным разделом в JSON, HTML и PDF. JSON сохраняет legacy-поля и содержит `schema_version: "2.0"`.

## DefectDojo

```bash
mortyscan scan example.com --defectdojo-url https://dojo.example \
  --defectdojo-key "$DD_API_KEY" --defectdojo-engagement-id 123
```

Все три параметра обязательны. Отправка — явный внешний side effect; используется HTTPS `/api/v2/import-scan/`, SARIF multipart file и `Authorization: Token ...`. WARNING-лог содержит только hostname и engagement ID, без ключа. `--no-external` блокирует загрузку. API key удаляется из scan context и никогда не включается в findings/отчёты.
