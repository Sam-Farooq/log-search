"""The only part of this package that talks to a cluster.

It is separate so the rest stays pure: the templates, the field walk, the value
checks and the query builder are all offline, and the tests for them need
nothing running. This module is exercised by the tests marked `live`, which run
against the CI service container and nowhere else.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any

from elasticsearch import Elasticsearch

from logsearch.ingest import DocumentResult, bulk_operations
from logsearch.templates import TemplateSet

DEFAULT_URL = "http://localhost:9200"


def connect(url: str | None = None, request_timeout: int = 20) -> Elasticsearch:
    """A client, with no retry on timeout.

    Retrying a bulk request that timed out can index the batch twice, and the
    `create` action in bulk_operations is what makes that safe. Retrying on a
    connection error is fine, so that one is left on.
    """
    return Elasticsearch(
        url or os.environ.get("ELASTICSEARCH_URL", DEFAULT_URL),
        request_timeout=request_timeout,
        retry_on_timeout=False,
        max_retries=2,
    )


def install(client: Elasticsearch, templates: TemplateSet) -> list[tuple[str, str]]:
    """Apply every step in bootstrap-order.json, in that order."""
    applied: list[tuple[str, str]] = []
    for step in templates.bootstrap_steps:
        kind = step["kind"]
        name = step["name"]
        if kind == "write_index":
            if client.indices.exists(index=name):
                applied.append((name, "exists"))
                continue
            client.indices.create(index=name, aliases={step["alias"]: {"is_write_index": True}})
            applied.append((name, "created"))
            continue

        body = json.loads((templates.directory / step["file"]).read_text(encoding="utf-8"))
        if kind == "ilm_policy":
            client.ilm.put_lifecycle(name=name, policy=body["policy"])
        elif kind == "component_template":
            client.cluster.put_component_template(
                name=name, template=body["template"], meta=body.get("_meta")
            )
        elif kind == "index_template":
            client.indices.put_index_template(
                name=name,
                index_patterns=body["index_patterns"],
                composed_of=body.get("composed_of", []),
                priority=body.get("priority", 0),
                template=body.get("template"),
                meta=body.get("_meta"),
            )
        else:
            raise ValueError(f"unknown bootstrap step kind {kind!r}")
        applied.append((name, "put"))
    return applied


@dataclass
class BulkOutcome:
    indexed: int = 0
    failed: int = 0
    conflicts: int = 0
    """Already present. With `create` and an event id, a retried batch lands here."""
    failures: list[tuple[str, str, str]] = dataclass_field(default_factory=list)
    """Document id, error type, reason, straight from the bulk item."""

    @property
    def ok(self) -> bool:
        return self.failed == 0


def bulk_index(
    client: Elasticsearch,
    results: list[DocumentResult],
    alias: str,
    refresh: bool = True,
) -> BulkOutcome:
    """Send the accepted documents and read every item in the response.

    A bulk request returns 200 with per item errors. Checking the HTTP status
    and stopping there is how a batch reports success while losing half of
    itself.
    """
    operations = bulk_operations(results, alias)
    outcome = BulkOutcome()
    if not operations:
        return outcome
    response = client.bulk(operations=operations, refresh=refresh)
    for item in response.get("items", []):
        action = next(iter(item.values()))
        status = action.get("status", 0)
        if status == 409:
            outcome.conflicts += 1
        elif 200 <= status < 300:
            outcome.indexed += 1
        else:
            error = action.get("error") or {}
            outcome.failed += 1
            outcome.failures.append(
                (
                    str(action.get("_id")),
                    str(error.get("type", "unknown")),
                    str(error.get("reason", "")),
                )
            )
    return outcome


def search(client: Elasticsearch, target: str, body: dict[str, Any]) -> dict[str, Any]:
    return dict(client.search(index=target, body=body))


def ignored_fields(client: Elasticsearch, target: str, size: int = 200) -> dict[str, int]:
    """Which fields the cluster threw away, counted from the hits themselves.

    `_ignored` is per document metadata, so this reads it off each hit rather
    than aggregating. That caps at `size` documents and is the honest way to
    get the list without claiming an exact count over a large index.
    """
    response = client.search(
        index=target,
        size=size,
        query={"exists": {"field": "_ignored"}},
        source=False,
    )
    counts: dict[str, int] = {}
    for hit in response.get("hits", {}).get("hits", []):
        for path in hit.get("_ignored", []):
            counts[path] = counts.get(path, 0) + 1
    return counts


def rollover(client: Elasticsearch, alias: str) -> str:
    """Roll the alias and return the new write index.

    The writer is unaffected, which is the only reason an alias is used instead
    of an index name: nothing that produces logs has to learn the new name.
    """
    response = client.indices.rollover(alias=alias)
    return str(response["new_index"])


def write_index_of(client: Elasticsearch, alias: str) -> str | None:
    """The one index behind an alias that accepts writes.

    An alias over several indices with none of them claiming the write refuses
    every write with an illegal_argument_exception, and the message arrives at
    the producer rather than anywhere near this repository.
    """
    for index, info in client.indices.get_alias(name=alias).items():
        if info.get("aliases", {}).get(alias, {}).get("is_write_index"):
            return str(index)
    return None
