# `openapi` — OpenAPI checks

Explicitly enable with `--active --openapi`. The module searches common in-scope OpenAPI/Swagger locations and makes bounded read-only GET/HEAD/OPTIONS checks. It never submits POST/PUT/PATCH/DELETE or mass-assignment mutations. Schemathesis is an optional `.[api]` extra; without it, limited built-in schema parsing remains available. Requests honor the shared scope, proxy, headers/cookies and rate limiter; `--no-external` blocks optional external enrichment/tools.
