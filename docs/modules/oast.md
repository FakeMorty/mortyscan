# `oast` — Interactsh

OAST выключен по умолчанию. Установите ProjectDiscovery `interactsh-client`, затем явно запускайте скан:

```bash
mortyscan scan example.com --active --oast --i-own-this-target
# optional custom server
mortyscan scan example.com --active --oast --interactsh-url https://oast.example --i-own-this-target
```

Базовый режим регистрирует уникальный payload на каждую проверку, затем отправляет максимум 12 in-scope read-only GET probes и опрашивает Interactsh каждые 5 секунд до 60 секунд. Проверяются обнаруженные GET-параметры и `X-Forwarded-Host`/`Host`. Callback подтверждает OOB-взаимодействие, но сам по себе не доказывает RCE или чтение данных.

POST-эффекты по умолчанию запрещены. Дополнительный режим XXE/webhook доступен только для найденных same-scope POST forms:

```bash
mortyscan scan example.com --active --oast --oast-write-probes --i-own-this-target
# В интерактивном терминале введите ровно: OAST POST PROBES
```

Он отправляет не более двух POST probes (JSON webhook field / XML external entity), и может изменить состояние приложения или запустить его интеграции. Флаг запрещён вместе с `--yes` и в CI; требуется отдельное точное TTY-подтверждение. Никогда не включайте этот режим против чужих систем.

Запуск OAST — внешний эффект: запросы отправляются выбранному OAST серверу и цели, поэтому событие логируется с `WARNING`. Учитываются proxy, scope, общая rate limit и process-group timeout; payloads/interactions хранятся только во временном каталоге и correlation IDs не раскрываются в findings. Без бинарника модуль gracefully пропускается; `--no-external` блокирует запуск.
