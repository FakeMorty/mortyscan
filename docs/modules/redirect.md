# Open Redirect

Активно тестирует GET-параметры, собранные краулером, а также типовые имена параметров на уже известных URL.
По умолчанию отправляет максимум 60 запросов с частотой не выше `--rate-limit`.

Редиректы не проходят автоматически: сканер проверяет `Location` и не обращается к внешнему адресу.
HTML-находка считается предварительной только при сочетании контрольного hostname и `meta refresh`/`window.location`.
POST-формы не отправляются.

```bash
mortyscan scan https://owned.example --active --i-own-this-target --modules crawler,redirect
```
