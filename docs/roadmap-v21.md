# Roadmap — v21+

Items outside the v19–v20 delivery scope; none are enabled as part of the v20 work:

- HTTP request smuggling analysis (requires a dedicated protocol-safe design and isolated lab coverage).
- Prototype pollution analysis with a controlled JavaScript runtime.
- Race-condition testing with explicit concurrency and state-reset controls.
- Web UI.
- Automated exploit generation or post-exploitation.

All future active tests should preserve explicit authorization gates, scope enforcement, rate limits, bounded timeouts, and harmless defaults. Do not infer that a roadmap item has been implemented merely because it appears here.
