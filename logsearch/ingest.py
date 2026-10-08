"""The ingest path: decide what a document becomes before it reaches a cluster.

Three strategies, run over the same events, because the argument about mapping
conflicts is not settled by naming a setting. It is settled by counting what
each one costs on the same input.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import StrEnum
from typing import Any

from logsearch.conflicts import Check, Verdict, check_value
from logsearch.fields import FieldMap


class Strategy(StrEnum):
    STRICT = "strict"
    IGNORE_MALFORMED = "ignore-malformed"
    NORMALIZE = "normalize"


class StrategyMismatch(Exception):
    """The strategy asked for is not the one this mapping implements."""


@dataclass(frozen=True)
class FieldOutcome:
    path: str
    verdict: Verdict
    reason: str
    value: Any = None


@dataclass
class DocumentResult:
    event_id: str
    accepted: bool
    document: dict[str, Any] | None = None
    rejection: str | None = None
    not_indexed: list[FieldOutcome] = dataclass_field(default_factory=list)
    """In `_source`, absent from the index. Nothing in the response says so."""
    repaired: list[FieldOutcome] = dataclass_field(default_factory=list)
    routed_to_catch_all: list[str] = dataclass_field(default_factory=list)
    diverted: bool = False
    """Held back by the ingest path rather than sent and lost."""


@dataclass
class IngestReport:
    strategy: Strategy
    mapping: str
    accepted: int = 0
    rejected: int = 0
    diverted: int = 0
    documents_with_silent_loss: int = 0
    silent_field_losses: Counter[str] = dataclass_field(default_factory=Counter)
    repairs: Counter[str] = dataclass_field(default_factory=Counter)
    routed_keys: Counter[str] = dataclass_field(default_factory=Counter)
    rejections: Counter[str] = dataclass_field(default_factory=Counter)

    @property
    def total(self) -> int:
        return self.accepted + self.rejected + self.diverted

    @property
    def silently_lost_values(self) -> int:
        return sum(self.silent_field_losses.values())

    def add(self, result: DocumentResult) -> None:
        if result.diverted:
            self.diverted += 1
        elif result.accepted:
            self.accepted += 1
        else:
            self.rejected += 1
            if result.rejection:
                self.rejections[result.rejection.split(":")[0]] += 1
        if result.accepted and result.not_indexed:
            self.documents_with_silent_loss += 1
        for loss in result.not_indexed:
            self.silent_field_losses[loss.path] += 1
        for repair in result.repaired:
            self.repairs[repair.path] += 1
        for key in result.routed_to_catch_all:
            self.routed_keys[key] += 1


def leaf_paths(
    document: dict[str, Any], field_map: FieldMap, prefix: str = ""
) -> list[tuple[str, Any]]:
    """Dotted path and value for every point where the mapping stops.

    The walk descends only through keys the mapping declares as objects. It
    stops at three other kinds of key, and each stop matters:

    a mapped leaf, because the value belongs to that field whatever shape it
    arrived in. Descending into an object sent to `event.duration_ms` invents
    `event.duration_ms.value`, a path that can never exist, and then reports
    an unknown key instead of the type conflict that is actually there;

    a flattened root, because everything under it is one value as far as the
    mapping is concerned;

    an unmapped key, at the shallowest point it is unmapped, because that is
    where Elasticsearch stops too. A strict mapping handed `{"k8s": {...}}`
    names `[k8s]` in the exception, not a leaf three levels down.
    """
    out: list[tuple[str, Any]] = []
    for key, value in document.items():
        path = f"{prefix}{key}"
        mapped = field_map.get(path)
        if mapped is None or mapped.kind != "object":
            out.append((path, value))
            continue
        if isinstance(value, dict) and value:
            out.extend(leaf_paths(value, field_map, f"{path}."))
        else:
            out.append((path, value))
    return out


def dotted_keys(value: Any, prefix: str) -> dict[str, Any]:
    """Flatten an unmapped subtree into dotted keys for the catch-all.

    A flattened field has a depth_limit, so putting the subtree in whole can
    cost the whole value. Dotted keys stay at depth one and read the same way
    in a query.
    """
    if not isinstance(value, dict) or not value:
        return {prefix: value}
    out: dict[str, Any] = {}
    for key, sub in value.items():
        out.update(dotted_keys(sub, f"{prefix}.{key}"))
    return out


def _assign(document: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    node = document
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def catch_all_root(field_map: FieldMap) -> str | None:
    roots = field_map.flattened_roots()
    return roots[0] if roots else None


def prepare(raw: dict[str, Any], field_map: FieldMap, strategy: Strategy) -> DocumentResult:
    """Turn one raw event into the document that would be sent, or refuse it."""
    lenient = field_map.composed.index_ignore_malformed
    if strategy is Strategy.IGNORE_MALFORMED and not lenient:
        raise StrategyMismatch(
            f"{field_map.composed.name} sets index.mapping.ignore_malformed false, so "
            f"it cannot be run under the ignore-malformed strategy. Compose "
            f"logs-app-lenient instead."
        )
    if strategy is not Strategy.IGNORE_MALFORMED and lenient:
        raise StrategyMismatch(
            f"{field_map.composed.name} turns ignore_malformed on for every field, so "
            f"the {strategy.value} strategy cannot be observed against it."
        )

    event_id = str(raw.get("event", {}).get("id", "")) or "<no event.id>"
    result = DocumentResult(event_id=event_id, accepted=True, document={})
    catch_all = catch_all_root(field_map)
    dynamic = field_map.composed.dynamic
    extras: dict[str, Any] = {}

    for path, value in leaf_paths(raw, field_map):
        mapped = field_map.get(path)
        if mapped is None:
            _handle_unmapped(result, path, value, catch_all, dynamic, strategy, extras)
            if not result.accepted:
                return result
            continue

        check = check_value(value, mapped, field_map.definition(path))
        if not _handle_checked(result, path, value, check, strategy):
            return result
        # A multi-field is a second index structure over the same value, and it
        # can fail on its own. `message` is text with no length limit and
        # `message.raw` is a keyword with ignore_above 1024, so a long line is
        # searchable and ungroupable at the same time, with nothing in the
        # write response to say which half is missing.
        for sub_path, sub_field in field_map.multi_fields_of(path):
            sub_check = check_value(value, sub_field, field_map.definition(sub_path))
            if not sub_check.indexed:
                result.not_indexed.append(
                    FieldOutcome(sub_path, sub_check.verdict, sub_check.reason, value)
                )

    if extras and catch_all:
        existing = result.document.setdefault(catch_all, {}) if result.document else {}
        if isinstance(existing, dict):
            existing.update(extras)
        else:
            result.document[catch_all] = extras

    return result


def _handle_unmapped(
    result: DocumentResult,
    path: str,
    value: Any,
    catch_all: str | None,
    dynamic: str,
    strategy: Strategy,
    extras: dict[str, Any],
) -> None:
    if catch_all is not None and strategy in {Strategy.STRICT, Strategy.NORMALIZE}:
        routed = dotted_keys(value, path)
        extras.update(routed)
        result.routed_to_catch_all.extend(sorted(routed))
        return
    if dynamic == "strict":
        result.accepted = False
        result.rejection = (
            f"strict_dynamic_mapping_exception: mapping set to strict, dynamic "
            f"introduction of [{path}] within [_doc] is not allowed"
        )
        if strategy is Strategy.NORMALIZE:
            result.diverted = True
        return
    if dynamic == "false":
        result.not_indexed.append(
            FieldOutcome(
                path,
                Verdict.UNMAPPED,
                f"{path}: dynamic is false, so this key is kept in _source and never "
                f"indexed. It reads back in a hit and matches nothing",
                value,
            )
        )
        if result.document is not None:
            _assign(result.document, path, value)
        return
    # dynamic is true, which is the default and the reason mapping explosions
    # happen. The document indexes, the field is searchable, and the mapping is
    # one entry larger for every distinct key that has ever arrived. A cluster
    # state holds that mapping, every node holds the cluster state, and the key
    # came from a request body.
    result.not_indexed.append(
        FieldOutcome(
            path,
            Verdict.UNMAPPED,
            f"{path}: dynamic is true, so this key is added to the mapping on arrival "
            f"and counts against total_fields.limit from now on",
            value,
        )
    )
    if result.document is not None:
        _assign(result.document, path, value)


def _handle_checked(
    result: DocumentResult, path: str, value: Any, check: Check, strategy: Strategy
) -> bool:
    document = result.document
    assert document is not None

    if check.verdict in {Verdict.OK, Verdict.COERCED}:
        _assign(document, path, value)
        return True

    if check.verdict is Verdict.OVER_IGNORE_ABOVE:
        _assign(document, path, value)
        result.not_indexed.append(FieldOutcome(path, check.verdict, check.reason, value))
        return True

    if check.verdict is Verdict.SHAPE:
        result.accepted = False
        result.rejection = f"document_parsing_exception: {check.reason}"
        result.diverted = strategy is Strategy.NORMALIZE
        return False

    # Verdict.MALFORMED, which is where the three strategies part company.
    if strategy is Strategy.IGNORE_MALFORMED:
        _assign(document, path, value)
        result.not_indexed.append(
            FieldOutcome(
                path,
                check.verdict,
                f"{check.reason}. ignore_malformed is on, so the document indexes with "
                f"a 201 and this field is in _source, out of the index, and named in "
                f"_ignored",
                value,
            )
        )
        return True

    if strategy is Strategy.NORMALIZE and check.normalized is not None:
        _assign(document, path, check.normalized)
        result.repaired.append(FieldOutcome(path, check.verdict, check.reason, check.normalized))
        return True

    result.accepted = False
    result.rejection = f"document_parsing_exception: {check.reason}"
    result.diverted = strategy is Strategy.NORMALIZE
    return False


def run(
    events: list[dict[str, Any]], field_map: FieldMap, strategy: Strategy
) -> tuple[IngestReport, list[DocumentResult]]:
    report = IngestReport(strategy=strategy, mapping=field_map.composed.name)
    results = [prepare(event, field_map, strategy) for event in events]
    for result in results:
        report.add(result)
    return report, results


def bulk_operations(
    results: list[DocumentResult], alias: str, use_create: bool = True
) -> list[dict[str, Any]]:
    """The `operations` payload for the official client's bulk call.

    `create` with the event id as `_id` makes a retried batch idempotent, and
    costs a 409 per duplicate that the caller has to read as success rather
    than failure. It is idempotent only within one index: after a rollover the
    same id lands in the new write index and the 409 never happens, so this
    de-duplicates a retry and not a replay.
    """
    operations: list[dict[str, Any]] = []
    for result in results:
        if not result.accepted or result.document is None:
            continue
        action = "create" if use_create else "index"
        header: dict[str, Any] = {action: {"_index": alias}}
        if use_create and result.event_id != "<no event.id>":
            header[action]["_id"] = result.event_id
        operations.append(header)
        operations.append(result.document)
    return operations
