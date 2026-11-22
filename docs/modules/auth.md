# `auth` — authenticated scans

Use `--cookie` and repeatable `--header` to pass credentials to the shared HTTP client. Form login uses `--login-url` with `--login-creds user:pass`; credentials are validated before network access and login state is kept in the scan context. `--account-b` enables an isolated second account session for permitted BOLA checks:

```bash
mortyscan scan https://example.com --active --login-url https://example.com/login --login-creds 'alice:secret' --account-b 'bob:secret' --i-own-this-target
```

Login and account comparison require explicit active permission. Sensitive values are not written into findings/log output; credentials are restricted to the target origin. Use dedicated, disposable test accounts.
