"""Explicit, bounded GraphQL schema bypass and field-suggestion probes."""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

import httpx

from ..core import Finding, ScanContext, Severity, host_in_scope
from .crawler import _registrable
from .graphql import CANDIDATES

NAME = "graphql_deep"
REQUIRES_INTRUSIVE = True
REQUIRES_STRESS = False
MAX_RESPONSE = 512 * 1024
TYPE_WORDLIST = (
    "User", "Admin", "Account", "Order", "Payment", "Product", "Customer", "Invoice",
    "Session", "Token", "Role", "Permission", "Organization", "Team", "Node", "Query",
    "Mutation", "File", "Upload", "Message", "Profile", "Address", "Subscription",
)
_SUGGESTION_RE = re.compile(r"Did you mean\s+([^?]+)\??", re.I)
_FIELD_RE = re.compile(r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]")


def _in_scope(ctx: ScanContext, url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False
        scope = set(ctx.config.get("scope_hosts", []))
        if scope:
            return host_in_scope(parsed.hostname, scope)
        return _registrable(parsed.hostname) == _registrable(ctx.target)
    except Exception:
        return False


async def _post(client: httpx.AsyncClient, url: str, query: str, *, headers=None):
    try:
        async with client.stream("POST", url, json={"query": query}, headers=headers,
                                 follow_redirects=False) as response:
            chunks = []
            total = 0
            async for chunk in response.aiter_bytes():
                if total >= MAX_RESPONSE:
                    break
                piece = chunk[:MAX_RESPONSE - total]
                chunks.append(piece)
                total += len(piece)
            raw = b"".join(chunks)
            try:
                body = json.loads(raw.decode("utf-8", errors="replace"))
            except Exception:
                body = {}
            return response.status_code, body
    except Exception:
        return None


async def _discover_endpoints(ctx: ScanContext, client: httpx.AsyncClient) -> list[str]:
    known = set(ctx.config.get("graphql_endpoints", []) or [])
    for path in CANDIDATES:
        url = urljoin(ctx.base_url.rstrip("/") + "/", path.lstrip("/"))
        if not _in_scope(ctx, url):
            continue
        result = await _post(client, url, "{ __typename }")
        if result and result[0] in {200, 400}:
            payload = result[1]
            if isinstance(payload, dict) and ("data" in payload or "errors" in payload):
                known.add(url)
    return sorted(url for url in known if _in_scope(ctx, url))[:10]


def _collect_suggestions(payload: dict) -> set[str]:
    suggestions = set()
    for error in payload.get("errors", []) if isinstance(payload, dict) else []:
        message = str(error.get("message", "")) if isinstance(error, dict) else str(error)
        for found in _SUGGESTION_RE.findall(message):
            suggestions.update(_FIELD_RE.findall(found))
    return suggestions


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    if not ctx.config.get("graphql_deep_enabled"):
        return
    if not ctx.permissions.get("intrusive"):
        ctx.add(Finding(module=NAME, title="Глубокий GraphQL-аудит пропущен: нет активного разрешения",
                        severity=Severity.INFO, source="permission gate", confidence="high"))
        return
    endpoints = await _discover_endpoints(ctx, client)
    if not endpoints:
        ctx.add(Finding(module=NAME, title="Deep GraphQL: endpoint не обнаружен", severity=Severity.INFO))
        return

    tested = 0
    type_names: set[str] = set()
    field_names: set[str] = set()
    suggestions: set[str] = set()
    introspection_enabled = False
    for endpoint in endpoints:
        probe = await _post(client, endpoint,
                            "{ __schema { types { name } queryType { name } mutationType { name } } }")
        tested += 1
        if probe and probe[0] == 200 and isinstance(probe[1], dict):
            schema = (probe[1].get("data") or {}).get("__schema")
            if isinstance(schema, dict):
                introspection_enabled = True
                type_names.update(str(item.get("name")) for item in schema.get("types", [])
                                  if isinstance(item, dict) and item.get("name") and not str(item["name"]).startswith("__"))
                mutation = schema.get("mutationType") or {}
                mutation_name = mutation.get("name") if isinstance(mutation, dict) else None
                if mutation_name:
                    field_names.add(str(mutation_name))
                continue
        # Clairvoyance-style, low-volume type probes when full introspection is disabled.
        for type_name in TYPE_WORDLIST:
            result = await _post(client, endpoint,
                                 f'{{ __type(name: "{type_name}") {{ name fields {{ name }} }} }}')
            tested += 1
            if not result or not isinstance(result[1], dict):
                continue
            payload = result[1]
            typed = (payload.get("data") or {}).get("__type") if isinstance(payload.get("data"), dict) else None
            if isinstance(typed, dict):
                if typed.get("name"):
                    type_names.add(str(typed["name"]))
                field_names.update(str(item.get("name")) for item in typed.get("fields", [])
                                   if isinstance(item, dict) and item.get("name"))
            suggestions.update(_collect_suggestions(payload))
            if tested >= 50:
                break
        if tested >= 50:
            break

    if introspection_enabled:
        ctx.add(Finding(module=NAME, title="Deep GraphQL: схема доступна через introspection",
                        severity=Severity.MEDIUM, cwe="CWE-200",
                        evidence=f"types_found={len(type_names)}; mutation_root={next(iter(field_names), 'none')}",
                        description="Полная introspection доступна. Schema details ограничены агрегированными именами; response bodies не сохранялись.",
                        remediation="Отключите introspection в production, если она не нужна публичным клиентам.",
                        source="GraphQL introspection", confidence="high", tags=["graphql", "introspection"]))
    else:
        if type_names or field_names or suggestions:
            ctx.add(Finding(module=NAME, title="Deep GraphQL: типы/поля раскрыты при выключенной introspection",
                            severity=Severity.MEDIUM,
                            evidence=f"types={len(type_names)}; fields={len(field_names)}; suggestions={len(suggestions)}",
                            description="Точечные __type-запросы или ошибки валидации раскрыли имена типов/полей.",
                            source="GraphQL type probes", confidence="medium",
                            raw={"types": sorted(type_names)[:30], "fields": sorted(field_names)[:50],
                                 "suggestions": sorted(suggestions)[:50]}))
        else:
            ctx.add(Finding(module=NAME, title="Deep GraphQL: introspection и type probes не раскрыли схему",
                            severity=Severity.INFO,
                            description="Проверено ограниченное имя-слово для распространённых GraphQL-типов."))

    batch_enabled = bool(ctx.config.get("graphql_load_tests")
                         and ctx.config.get("graphql_load_tests_confirmed"))
    if ctx.config.get("graphql_load_tests") and not batch_enabled:
        ctx.add(Finding(module=NAME, title="GraphQL batch пропущен: нет TTY-подтверждения",
                        severity=Severity.INFO, source="runtime permission gate", confidence="high"))
    if batch_enabled:
        # This is an explicitly confirmed single request; no 20-level recursion or mutation is sent.
        query = "query MortyBatch { " + " ".join(f"a{i}: __typename" for i in range(100)) + " }"
        for endpoint in endpoints:
            response = await _post(client, endpoint, query)
            tested += 1
            if response and response[0] == 200 and "errors" not in response[1]:
                ctx.add(Finding(module=NAME, title="GraphQL принимает alias batch из 100 полей",
                                severity=Severity.LOW, url=endpoint,
                                evidence="100 alias-запросов обработаны одним GraphQL request; response body не сохранялся.",
                                description="Это небольшой smoke-test, не нагрузочный тест. Большие batch-запросы могут увеличивать расход ресурсов.",
                                source="explicit GraphQL load probe", confidence="medium",
                                tags=["graphql", "batch", "explicit-load-test"]))
                break

    ctx.config["graphql_type_names"] = sorted(type_names)[:100]
    ctx.config["graphql_field_suggestions"] = sorted(field_names | suggestions)[:100]
    ctx.add(Finding(module=NAME, title=f"Deep GraphQL завершён: endpoints {len(endpoints)}, probes {tested}",
                    severity=Severity.INFO,
                    description="Мутации и глубокие рекурсивные запросы не отправлялись. Batch 100 aliases выполняется только при отдельном флаге с TTY-подтверждением.",
                    raw={"endpoints": endpoints, "probes": tested, "introspection_enabled": introspection_enabled,
                         "type_names": len(type_names), "field_suggestions": len(field_names | suggestions),
                         "batch_test_enabled": batch_enabled,
                         "mutation_tests": False, "deep_query_tests": False}))
