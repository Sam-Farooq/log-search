"""The tests that need a cluster, and the only ones that can prove the model.

Everything else in this suite asserts that `logsearch.conflicts` agrees with
itself. These assert that it agrees with Elasticsearch. They are marked `live`
and excluded by default; CI runs them with `-m live` against the service
container.

    ELASTICSEARCH_URL=http://localhost:9200 pytest -m live
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from logsearch.fields import FieldMap, FieldUsageError
from logsearch.ingest import Strategy, run
from logsearch.query import LogQuery

pytestmark = pytest.mark.live

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
TYPE_CASES = json.loads((FIXTURES / "type-cases.json").read_text(encoding="utf-8"))["cases"]
STRICT_INDEX = "live-strict"
LENIENT_INDEX = "live-lenient"


@pytest.fixture(scope="module")
def client():
    elasticsearch = pytest.importorskip("elasticsearch")
    from logsearch.client import connect

    found = connect()
    try:
        found.info()
    except elasticsearch.ApiError:  # pragma: no cover
        raise
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"no cluster: {exc}")
    return found


@pytest.fixture(scope="module")
def events() -> list[dict]:
    lines = (FIXTURES / "events.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _create(client, templates, index: str, template_name: str) -> None:
    """Create one index with a composed mapping, directly.

    The index templates are installed too, in test_install_is_accepted. These
    direct creates exist so one test can fail on one mapping without the order
    of the others mattering.
    """
    composed = templates.compose(template_name)
    client.options(ignore_status=404).indices.delete(index=index)
    settings = {
        key: value
        for key, value in composed.settings.items()
        if not key.startswith("index.lifecycle")
    }
    settings["index.number_of_replicas"] = 0
    client.indices.create(index=index, settings=settings, mappings=composed.mappings)


@pytest.fixture(scope="module")
def strict_index(client, templates):
    _create(client, templates, STRICT_INDEX, "logs-app")
    return STRICT_INDEX


@pytest.fixture(scope="module")
def lenient_index(client, templates):
    _create(client, templates, LENIENT_INDEX, "logs-app-lenient")
    return LENIENT_INDEX


def test_install_is_accepted_in_the_order_bootstrap_declares(client, templates):
    from logsearch.client import install, write_index_of

    applied = install(client, templates)
    assert [name for name, _ in applied][:2] == ["logs-app", "logs-audit"]
    assert len(applied) == 10
    assert write_index_of(client, "logs-app") == "logs-app-000001"


def test_the_composed_mapping_is_accepted_as_written(client, strict_index, templates):
    """If this fails, the file is not a mapping, whatever the lint says."""
    mapping = client.indices.get_mapping(index=strict_index)[strict_index]["mappings"]
    assert mapping["dynamic"] == "strict"
    assert mapping["properties"]["labels"]["type"] == "flattened"
    assert mapping["properties"]["message"]["fields"]["raw"]["ignore_above"] == 1024


def test_a_field_limit_below_the_mapping_is_rejected_by_the_cluster(client, templates):
    import elasticsearch

    composed = templates.compose("logs-app")
    client.options(ignore_status=404).indices.delete(index="live-too-small")
    with pytest.raises(elasticsearch.BadRequestError) as caught:
        client.indices.create(
            index="live-too-small",
            settings={"index.mapping.total_fields.limit": 10},
            mappings=composed.mappings,
        )
    assert "limit of total fields" in str(caught.value)


@pytest.mark.parametrize("case_index", range(len(TYPE_CASES)), ids=[c["field"] for c in TYPE_CASES])
def test_the_type_table_agrees_with_the_parser(client, strict_index, lenient_index, case_index):
    """One row of fixtures/type-cases.json, replayed against both mappings.

    ok and coerced index cleanly under strict. malformed is rejected by strict
    and accepted by lenient with the field in _ignored. shape is rejected by
    both, because ignore_malformed does not cover an object sent to a scalar.
    """
    case = TYPE_CASES[case_index]
    document = {"@timestamp": "2026-03-01T00:00:00Z", "event": {"id": f"case-{case_index}"}}
    node = document
    parts = case["field"].split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = case["value"]

    strict = client.options(ignore_status=400).index(
        index=strict_index, id=f"case-{case_index}", document=document, refresh=True
    )
    lenient = client.options(ignore_status=400).index(
        index=lenient_index, id=f"case-{case_index}", document=document, refresh=True
    )
    strict_ok = strict.meta.status < 300
    lenient_ok = lenient.meta.status < 300

    if case["verdict"] in {"ok", "coerced"}:
        assert strict_ok, strict.body
        assert lenient_ok, lenient.body
    elif case["verdict"] == "malformed":
        assert not strict_ok, f"{case} indexed under the strict mapping"
        assert lenient_ok, lenient.body
        hit = client.get(index=lenient_index, id=f"case-{case_index}")
        assert case["field"] in (hit.body.get("_ignored") or [])
    else:
        assert not strict_ok, f"{case} indexed under the strict mapping"
        assert not lenient_ok, "ignore_malformed accepted an object sent to a scalar"


def test_the_strict_mapping_rejects_exactly_what_the_report_said(client, strict_index, app, events):
    from logsearch.client import bulk_index

    field_map = FieldMap(app)
    report, results = run(events, field_map, Strategy.STRICT)
    outcome = bulk_index(client, results, strict_index)
    assert outcome.failed == 0, outcome.failures
    assert outcome.indexed + outcome.conflicts == report.accepted == 31


def test_ignore_malformed_loses_the_fields_the_report_named(
    client, lenient_index, templates, events
):
    from logsearch.client import bulk_index, ignored_fields

    field_map = FieldMap(templates.compose("logs-app-lenient"))
    report, results = run(events, field_map, Strategy.IGNORE_MALFORMED)
    outcome = bulk_index(client, results, lenient_index)
    assert outcome.indexed + outcome.conflicts == report.accepted == 40
    dropped = ignored_fields(client, lenient_index)
    # _ignored records the field and never the value it held.
    assert dropped.get("event.duration_ms") == 5
    assert dropped.get("client.ip") == 1
    assert dropped.get("message.raw") == 1


def test_a_term_query_on_an_analysed_field_finds_nothing(client, strict_index, app):
    """The refusal in resolve(), demonstrated rather than asserted."""
    field_map = FieldMap(app)
    by_term = client.search(index=strict_index, size=0, query={"term": {"message": "Reconciled"}})
    by_match = client.search(index=strict_index, size=0, query={"match": {"message": "Reconciled"}})
    assert by_term["hits"]["total"]["value"] == 0
    assert by_match["hits"]["total"]["value"] > 0
    # Which is why the builder will not emit the first one.
    with pytest.raises(FieldUsageError):
        LogQuery(field_map).term("message", "Reconciled")


def test_a_range_on_log_level_drops_the_errors(client, strict_index, app):
    """gte: 'warn' over a keyword excludes error and fatal, and returns 200."""
    by_range = client.search(
        index=strict_index, size=0, query={"range": {"log.level": {"gte": "warn"}}}
    )
    body = LogQuery(FieldMap(app)).level_at_least("warn").page(0).body()
    by_terms = client.search(index=strict_index, body=body)
    assert by_range["hits"]["total"]["value"] < by_terms["hits"]["total"]["value"]
    levels = client.search(
        index=strict_index,
        size=0,
        aggs={"levels": {"terms": {"field": "log.level", "size": 10}}},
    )
    buckets = {b["key"] for b in levels["aggregations"]["levels"]["buckets"]}
    assert "error" in buckets


def test_an_aggregation_on_a_text_field_is_refused_by_the_cluster(client, strict_index):
    import elasticsearch

    with pytest.raises(elasticsearch.BadRequestError) as caught:
        client.search(index=strict_index, size=0, aggs={"m": {"terms": {"field": "message"}}})
    assert "Fielddata is disabled" in str(caught.value)
    on_the_keyword = client.search(
        index=strict_index, size=0, aggs={"m": {"terms": {"field": "message.raw"}}}
    )
    assert on_the_keyword["aggregations"]["m"]["buckets"]


def test_the_write_index_moves_and_the_alias_does_not(client, templates):
    from logsearch.client import install, rollover, write_index_of

    install(client, templates)
    before = write_index_of(client, "logs-app")
    after_name = rollover(client, "logs-app")
    assert after_name != before
    assert write_index_of(client, "logs-app") == after_name
    # The producer still writes to `logs-app` and has learned nothing.
    written = client.index(
        index="logs-app",
        document={
            "@timestamp": "2026-03-08T00:00:00Z",
            "message": "after the rollover",
            "event": {"id": "after-rollover"},
            "service": {"name": "checkout-api"},
        },
        refresh=True,
    )
    assert written["_index"] == after_name
    assert (
        client.search(index="logs-app", size=0, query={"match_all": {}})["hits"]["total"]["value"]
        >= 1
    )
