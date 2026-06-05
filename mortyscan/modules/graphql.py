"""Поиск GraphQL-эндпоинтов и проверка включённой интроспекции."""
from __future__ import annotations

import asyncio
from urllib.parse import urljoin

import httpx

from ..core import Finding, ScanContext, Severity

NAME = "graphql"
REQUIRES_INTRUSIVE = False  # запрос самой схемы — это нормальный API-вызов
REQUIRES_STRESS = False

CANDIDATES = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    "/query", "/api/query", "/gql", "/api/gql",
]

INTROSPECTION = {
    "query": "query IntrospectionQuery { __schema { types { name } queryType { name } } }"
}


async def _try(client: httpx.AsyncClient, url: str):
    try:
        r = await client.post(url, json=INTROSPECTION, timeout=8)
    except Exception:
        return None
    if r.status_code in (200, 400):
        try:
            data = r.json()
            if isinstance(data, dict) and "data" in data and data["data"]:
                if "__schema" in data["data"]:
                    return data["data"]["__schema"]
        except Exception:
            pass
    return None


async def run(ctx: ScanContext, client: httpx.AsyncClient) -> None:
    base = ctx.base_url
    found = []
    for path in CANDIDATES:
        url = urljoin(base, path)
        schema = await _try(client, url)
        if schema:
            types = [t["name"] for t in schema.get("types", []) if not t["name"].startswith("__")]
            qtype = (schema.get("queryType") or {}).get("name", "?")
            found.append((url, qtype, types[:30]))
            ctx.add(Finding(
                module=NAME,
                title=f"GraphQL с включённой интроспекцией: {path}",
                severity=Severity.MEDIUM, cwe="CWE-200",
                url=url,
                evidence=f"queryType={qtype}, типов в схеме: {len(types)}",
                description="GraphQL-эндпоинт отдаёт полную схему по запросу __schema. "
                            "Это даёт атакующему карту всего API: какие есть запросы, мутации, типы, "
                            "аргументы. Резко ускоряет поиск других уязвимостей.",
                remediation="Отключите интроспекцию в production. Для Apollo Server — `introspection: false`. "
                            "Для Express-GraphQL — параметр `disableIntrospection`.",
                raw={"types_sample": types[:30]},
            ))
    if not found:
        ctx.add(Finding(module=NAME, title="GraphQL-эндпоинт не обнаружен",
                        severity=Severity.INFO))
