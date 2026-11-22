# `tls_deep` — глубокая TLS-проверка

Дополнительная проверка SSLyze отключена по умолчанию. Установите optional extra и запускайте только для разрешённой цели:

```bash
pip install 'mortyscan[tls]'
mortyscan scan example.com --active --tls-deep --i-own-this-target
```

Модуль использует SSLyze API без внешней shell-команды, принимает только HTTPS, не выполняет renegotiation/эксплуатацию, и ограничивает общий анализ 90 секундами. Проверяются согласованные TLS версии/шифры, Heartbleed, ROBOT, информация о сертификате и HSTS. Если extra отсутствует, выдаётся INFO finding и скан продолжается. `--no-external` отключает глубокий скан.
