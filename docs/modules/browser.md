# `browser` — Playwright SPA analysis

Optional extra: `pip install -e '.[browser]'` followed by `playwright install chromium`. Enable explicitly with `--active --browser`; screenshots additionally require `--screenshots`.

The headless browser collects same-scope requests/endpoints and page diagnostics, and can check discovered reflection candidates. Proxy, headers/cookies, scope policy, and bounded page/context lifetime are inherited from the scan. Missing Playwright/browser runtime produces an INFO skip instead of failing the scan. Browser execution is active and should only be used on authorized targets.
