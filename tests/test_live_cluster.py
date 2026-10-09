"""The tests that need a cluster, and the only ones that can prove the model.

Everything else in this suite asserts that `logsearch.conflicts` agrees with
itself. These assert that it agrees with Elasticsearch. They are marked `live`
and excluded by default; the CI workflow is configured to run them with
`-m live` against a service container, and that workflow has not run.

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
    direct creates exist so each test owns an index nothing else writes to:
    _ignored counts are per index, and a shared one would be the sum of
    whatever ran first.
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


def _load(client, templates, index: str, template_name: str, events, strategy):
    """Create the index and bulk the accepted documents into it."""
    from logsearch.client import bulk_index

    _create(client, templates, index, template_name)
    field_map = FieldMap(templates.compose(template_name))
    report, results = run(events, field_map, strategy)
    return report, bulk_index(client, results, index)


@pytest.fixture(scope="module")
def type_case_strict(client, templates):
    _create(client, templates, "live-types-strict", "logs-app")
    return "live-types-strict"


@pytest.fixture(scope="module")
def type_case_lenient(client, templates):
    _create(client, templates, "live-types-lenient", "logs-app-lenient")
    return "live-types-lenient"


@pytest.fixture(scope="module")
def strict_index(client, templates, events):
    report, outcome = _load(client, templates, "live-strict", "logs-app", events, Strategy.STRICT)
    return "live-strict", report, outcome


@pytest.fixture(scope="module")
def lenient_index(client, templates, events):
    report, outcome = _load(
        client,
        templates,
        "live-lenient",
        "logs-app-lenient",
        events,
        Strategy.IGNORE_MALFORMED,
    )
    return "live-lenient", report, outcome


def test_install_is_accepted_in_the_order_bootstrap_declares(client, templates):
    from logsearch.client import install, write_index_of

    applied = install(client, templates)
    assert [name for name, _ in applied][:2] == ["logs-app", "logs-audit"]
    assert len(applied) == 10
    assert write_index_of(client, "logs-app") == "logs-app-000001"


def test_the_composed_mapping_is_accepted_as_written(client, strict_index):
    """If this fails, the file is not a mapping, whatever the lint says."""
    index = strict_index[0]
    mapping = client.indices.get_mapping(index=index)[index]["mappings"]
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
    assert "limit of total fields" in str(caught.value).lower()


@pytest.mark.parametrize("case_index", range(len(TYPE_CASES)), ids=[c["field"] for c in TYPE_CASES])
def test_the_type_table_agrees_with_the_parser(
    client, type_case_strict, type_case_lenient, case_index
):
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
        index=type_case_strict, id=f"case-{case_index}", document=document, refresh=True
    )
    lenient = client.options(ignore_status=400).index(
        index=type_case_lenient, id=f"case-{case_index}", document=document, refresh=True
    )
    strict_ok = strict.meta.status < 300
    lenient_ok = lenient.meta.status < 300

    if case["verdict"] in {"ok", "coerced"}:
        assert strict_ok, strict.body
        assert lenient_ok, lenient.body
    elif case["verdict"] == "malformed":
        assert not strict_ok, f"{case} indexed under the strict mapping"
        assert lenient_ok, lenient.body
        hit = client.get(index=type_case_lenient, id=f"case-{case_index}")
        assert case["field"] in (hit.body.get("_ignored") or [])
    else:
        assert not strict_ok, f"{case} indexed under the strict mapping"
        assert not lenient_ok, "ignore_malformed accepted an object sent to a scalar"


def test_the_strict_mapping_accepts_exactly_what_the_report_said(strict_index):
    _, report, outcome = strict_index
    assert outcome.failed == 0, outcome.failures
    assert outcome.indexed + outcome.conflicts == report.accepted == 31


def test_ignore_malformed_loses_the_fields_the_report_named(client, lenient_index):
    from logsearch.client import ignored_fields

    index, report, outcome = lenient_index
    assert outcome.indexed + outcome.conflicts == report.accepted == 40
    dropped = ignored_fields(client, index)
    # _ignored records the field and never the value it held.
    assert dropped.get("event.duration_ms") == 5
    assert dropped.get("client.ip") == 1
    assert dropped.get("message.raw") == 1


def test_a_term_query_on_an_analysed_field_finds_nothing(client, strict_index, app):
    """The refusal in resolve(), run against a cluster rather than asserted."""
    field_map = FieldMap(app)
    index = strict_index[0]
    by_term = client.search(index=index, size=0, query={"term": {"message": "Reconciled"}})
    by_match = client.search(index=index, size=0, query={"match": {"message": "Reconciled"}})
    assert by_term["hits"]["total"]["value"] == 0
    assert by_match["hits"]["total"]["value"] > 0
    # Which is why the builder will not emit the first one.
    with pytest.raises(FieldUsageError):
        LogQuery(field_map).term("message", "Handled")


def test_a_range_on_log_level_drops_the_errors(client, strict_index, app):
    """gte: 'warn' over a keyword excludes error and fatal, and returns 200."""
    index, _, _ = strict_index
    by_range = client.search(index=index, size=0, query={"range": {"log.level": {"gte": "warn"}}})
    body = LogQuery(FieldMap(app)).level_at_least("warn").page(0).body()
    by_terms = client.search(index=index, body=body)
    assert by_range["hits"]["total"]["value"] < by_terms["hits"]["total"]["value"]
    levels = client.search(
        index=index,
        size=0,
        aggs={"levels": {"terms": {"field": "log.level", "size": 10}}},
    )
    buckets = {b["key"] for b in levels["aggregations"]["levels"]["buckets"]}
    assert "error" in buckets


def test_an_aggregation_on_a_text_field_is_refused_by_the_cluster(client, strict_index):
    import elasticsearch

    index = strict_index[0]

    with pytest.raises(elasticsearch.BadRequestError) as caught:
        client.search(index=index, size=0, aggs={"m": {"terms": {"field": "message"}}})
    assert "Fielddata is disabled" in str(caught.value)
    on_the_keyword = client.search(
        index=index, size=0, aggs={"m": {"terms": {"field": "message.raw"}}}
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
