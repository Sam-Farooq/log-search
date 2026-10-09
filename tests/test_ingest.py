from __future__ import annotations

import json
from pathlib import Path

import pytest

from logsearch.fields import FieldMap
from logsearch.ingest import (
    Strategy,
    StrategyMismatch,
    bulk_operations,
    leaf_paths,
    prepare,
    run,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _read(name: str) -> list[dict]:
    lines = (FIXTURES / name).read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


@pytest.fixture(scope="module")
def events() -> list[dict]:
    return _read("events.jsonl")


@pytest.fixture(scope="module")
def audit_events() -> list[dict]:
    return _read("audit-events.jsonl")


@pytest.fixture(scope="module")
def strict_map(app) -> FieldMap:
    return FieldMap(app)


@pytest.fixture(scope="module")
def lenient_map(templates) -> FieldMap:
    return FieldMap(templates.compose("logs-app-lenient"))


def test_the_fixture_file_is_the_size_its_readme_claims(events, audit_events):
    assert len(events) == 42
    assert len(audit_events) == 8


def test_leaf_paths_stops_at_a_mapped_leaf(strict_map):
    """An object sent to a scalar field is one value, not a subtree.

    Descending into it invents paths like event.duration_ms.unit, which can
    never exist in this mapping, and the real problem goes unreported.
    """
    paths = dict(leaf_paths({"event": {"duration_ms": {"value": 1400, "unit": "ms"}}}, strict_map))
    assert paths == {"event.duration_ms": {"value": 1400, "unit": "ms"}}


def test_leaf_paths_stops_at_a_flattened_root(strict_map):
    paths = dict(leaf_paths({"labels": {"tenant": "acme", "deep": {"a": 1}}}, strict_map))
    assert paths == {"labels": {"tenant": "acme", "deep": {"a": 1}}}


def test_leaf_paths_descends_through_real_objects(strict_map):
    paths = dict(leaf_paths({"http": {"response": {"status_code": 200, "bytes": 12}}}, strict_map))
    assert paths == {"http.response.status_code": 200, "http.response.bytes": 12}


def test_strict_rejects_malformed_values_and_still_loses_one_thing(events, strict_map):
    report, _ = run(events, strict_map, Strategy.STRICT)
    assert report.total == 42
    assert report.accepted == 31
    assert report.rejected == 11
    assert report.rejections == {"document_parsing_exception": 11}
    # Not zero. ignore_above is not ignore_malformed and a strict mapping does
    # not prevent it: one message is too long for its keyword half and loses
    # that half quietly. It is the only silent loss left under this strategy,
    # and the report names the field.
    assert report.silently_lost_values == 1
    assert dict(report.silent_field_losses) == {"message.raw": 1}


def test_ignore_malformed_accepts_nearly_everything_and_loses_values(events, lenient_map):
    report, _ = run(events, lenient_map, Strategy.IGNORE_MALFORMED)
    assert report.accepted == 39
    # Not zero, and this is the part people expect ignore_malformed to cover.
    # Three documents are rejected here exactly as they are under the strict
    # mapping: two send an object to a scalar field, and the third nests labels
    # deeper than the flattened depth_limit. A real cluster rejected that third
    # one with document_parsing_exception, which is how it stopped being
    # counted as a loss ignore_malformed absorbs.
    assert report.rejected == 3
    assert report.documents_with_silent_loss == 12
    assert report.silently_lost_values == 13
    assert report.silent_field_losses["event.duration_ms"] == 5
    assert report.silent_field_losses["@timestamp"] == 1
    assert report.silent_field_losses["client.ip"] == 1
    assert report.silent_field_losses["http.response.status_code"] == 1
    # dynamic: false keeps an unknown subtree in _source and out of the index,
    # reported at the shallowest unmapped key, which is where the cluster
    # stops as well.
    assert report.silent_field_losses["k8s"] == 1


def test_normalize_repairs_what_it_can_and_holds_back_the_rest(events, strict_map):
    report, results = run(events, strict_map, Strategy.NORMALIZE)
    assert report.accepted == 36
    assert report.diverted == 6
    assert report.rejected == 0
    assert report.silently_lost_values == 1
    assert report.repairs == {"event.duration_ms": 5}
    repaired = [r for r in results if r.repaired]
    assert {r.repaired[0].value for r in repaired} == {1400, 250, 120000, 900, 480}


def test_the_three_strategies_disagree_about_the_same_42_events(events, strict_map, lenient_map):
    strict, _ = run(events, strict_map, Strategy.STRICT)
    lenient, _ = run(events, lenient_map, Strategy.IGNORE_MALFORMED)
    normalized, _ = run(events, strict_map, Strategy.NORMALIZE)
    # The number that matters: values that ended up neither indexed nor
    # reported anywhere a writer would look.
    assert (strict.silently_lost_values, lenient.silently_lost_values) == (1, 13)
    assert normalized.silently_lost_values == 1
    # And how many of the 42 events reached the index at all.
    # 39 is also exactly what a real Elasticsearch indexed from the same 42
    # events under the lenient mapping, which is the point of the live suite.
    assert (strict.accepted, lenient.accepted, normalized.accepted) == (31, 39, 36)
    # The one loss the strict and normalize columns share is the same field in
    # the same event, and it is ignore_above rather than a type conflict.
    assert set(strict.silent_field_losses) == set(normalized.silent_field_losses) == {"message.raw"}


def test_a_long_message_loses_its_keyword_half_only(events, strict_map):
    """The document indexes. `message` is searchable. `message.raw` is not there.

    So the event can be found by a word in it and never appears in a terms
    aggregation over messages, and nothing in the write response says so.
    """
    long_message = next(e for e in events if len(e["message"]) > 1024)
    result = prepare(long_message, strict_map, Strategy.STRICT)
    assert result.accepted is True
    assert [loss.path for loss in result.not_indexed] == ["message.raw"]
    assert "ignore_above 1024" in result.not_indexed[0].reason


def test_unknown_keys_are_routed_into_the_catch_all(events, strict_map):
    report, results = run(events, strict_map, Strategy.STRICT)
    assert set(report.routed_keys) == {
        "tenant",
        "retry_count",
        "shard_hint",
        "k8s.pod.name",
        "k8s.node",
    }
    routed = next(r for r in results if "k8s.node" in r.routed_to_catch_all)
    assert routed.document["labels"]["k8s.node"] == "node-b"
    assert routed.accepted is True


def exp_keys_by_event(results) -> dict[str, set[str]]:
    """The generated `exp_*` keys each accepted document carries under `labels`.

    A helper rather than four lines inline, because the README and
    `fixtures/README.md` both state these counts and the only way to keep those
    numbers honest is to read them back off the same documents the ingest path
    produces.
    """
    by_event: dict[str, set[str]] = {}
    for result in results:
        document = result.document
        if not document or not isinstance(document.get("labels"), dict):
            continue
        exp = {key for key in document["labels"] if key.startswith("exp_")}
        if exp:
            by_event[document["event"]["id"]] = exp
    return by_event


def test_the_catch_all_turns_an_unbounded_key_set_into_one_mapped_field(events, strict_map):
    """Thirteen distinct keys arrive. The mapping gains none."""
    _, results = run(events, strict_map, Strategy.STRICT)
    keys: set[str] = set()
    for result in results:
        if result.document and isinstance(result.document.get("labels"), dict):
            keys |= set(result.document["labels"])
    assert len(keys) == 13
    assert len(FieldMap(strict_map.composed).flattened_roots()) == 1


def test_the_exp_keys_are_the_count_the_readme_states(events, strict_map):
    """Two events carry generated keys: 3 on one, 4 on the other, 7 distinct.

    The README claimed five per event for a while, which no assertion could
    contradict because the count above was a `>=`. These are equalities.
    """
    _, results = run(events, strict_map, Strategy.STRICT)
    by_event = exp_keys_by_event(results)
    assert {event: len(keys) for event, keys in by_event.items()} == {"e-0036": 3, "e-0037": 4}
    assert len(set.union(*by_event.values())) == 7
    assert set.intersection(*by_event.values()) == set()


def test_the_exp_key_count_moves_when_the_fixtures_do(events, strict_map):
    """The counts above have to fail on a fixture set that carries more keys.

    Five `exp_*` keys per event is what the README used to say. Feeding that
    shape through the same helper has to produce different numbers, or the
    equalities above are decoration.
    """
    doctored = json.loads(json.dumps(events))
    for event in doctored:
        labels = event.get("labels")
        if isinstance(labels, dict) and any(key.startswith("exp_") for key in labels):
            labels["exp_000001"] = "on"
            labels["exp_000002"] = "on"
    _, results = run(doctored, strict_map, Strategy.STRICT)
    by_event = exp_keys_by_event(results)
    assert {event: len(keys) for event, keys in by_event.items()} == {"e-0036": 5, "e-0037": 6}
    assert len(set.union(*by_event.values())) == 9
    assert set.intersection(*by_event.values()) == {"exp_000001", "exp_000002"}


def test_audit_rejects_an_unknown_key_because_it_has_no_catch_all(audit_events, templates):
    audit_map = FieldMap(templates.compose("logs-audit"))
    report, results = run(audit_events, audit_map, Strategy.STRICT)
    assert (report.accepted, report.rejected) == (6, 2)
    reasons = [r.rejection for r in results if r.rejection]
    assert all("strict_dynamic_mapping_exception" in reason for reason in reasons)
    assert any("request_body" in reason for reason in reasons)
    assert any("[labels]" in reason for reason in reasons)


def test_a_strategy_that_the_mapping_does_not_implement_is_refused(strict_map, lenient_map):
    with pytest.raises(StrategyMismatch, match="ignore_malformed false"):
        prepare({}, strict_map, Strategy.IGNORE_MALFORMED)
    with pytest.raises(StrategyMismatch, match="cannot be observed"):
        prepare({}, lenient_map, Strategy.STRICT)


def test_bulk_operations_pair_a_header_with_each_document(events, strict_map):
    _, results = run(events, strict_map, Strategy.STRICT)
    operations = bulk_operations(results, alias="logs-app")
    accepted = [r for r in results if r.accepted]
    assert len(operations) == len(accepted) * 2
    assert operations[0]["create"]["_index"] == "logs-app"
    assert operations[0]["create"]["_id"] == accepted[0].event_id
    assert operations[1] is accepted[0].document
    indexed = bulk_operations(results, alias="logs-app", use_create=False)
    assert "_id" not in indexed[0]["index"]
