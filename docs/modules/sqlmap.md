# `sqlmap` — SQLi verification

Requires an installed `sqlmap` executable and explicit `--active --sqlmap`. The module only considers SQLi candidates already reported by `vulns`; destructive-like paths (logout/delete/remove/unsubscribe) are excluded. The default and `--aggressive` profiles do not dump data. `--dump-data` is a separate highest-risk action requiring an interactive TTY and exact `YES`; it is rejected in CI/non-interactive mode. Per-URL timeouts are bounded by `--sqlmap-timeout` (maximum 180 seconds), output is parsed through the shared async process wrapper, and `--no-external` skips the tool.

```bash
mortyscan scan example.com --active --sqlmap --i-own-this-target
```
