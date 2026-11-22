# `csrf_audit` — form protection review

Passively reviews forms discovered by the crawler for common anti-CSRF controls (tokens and related attributes). It does not submit forms or mutate application state. Findings are heuristic and should be verified in the application context; absence of a token is not alone proof of an exploitable CSRF vulnerability. The crawler's in-scope request policy applies.
