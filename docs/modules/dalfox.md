# `dalfox` — opt-in XSS analysis

Requires the Dalfox binary and explicit `--active --dalfox`. Candidates are drawn from reflected parameters; known WAF targets are skipped unless `--aggressive` is selected. Configure the per-URL timeout with `--dalfox-timeout`; cookies/headers and proxy are passed only to the in-scope origin. JSON results are normalized into findings; raw secrets are redacted. `--no-external` prevents the binary from starting. OAST is separately gated by `--oast` and the configured Interactsh endpoint; it is not silently enabled by Dalfox.

```bash
mortyscan scan example.com --active --dalfox --i-own-this-target
```
