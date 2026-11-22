# `graphql_deep` — bounded GraphQL checks

Enable with `--active --graphql-deep`. The module performs bounded type/field-suggestion and depth checks on discovered in-scope GraphQL endpoints. Batch/load-style aliases are off by default; `--graphql-load-tests` requires a TTY and a separate exact confirmation, and is forbidden in CI. Intentionally mutating GraphQL operations are not submitted. Requests use shared scope, proxy, auth, and rate-limit controls.
