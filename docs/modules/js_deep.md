# `js_deep` — JavaScript and source-map analysis

The module inspects in-scope script URLs and browser-discovered endpoints, extracts API paths and candidate secrets/JWTs, and adds normalized endpoints/JWTs to `ScanContext`. Secret evidence is redacted/fingerprinted to reduce disclosure. Source map contents are only saved with the explicit `--save-sourcemaps` option and are bounded; treat saved sources as sensitive code. Requests use the shared HTTP client with rate, proxy, headers/cookies and scope protections.
