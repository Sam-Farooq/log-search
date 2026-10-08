from __future__ import annotations

import pytest

from logsearch.fields import FieldMap, FieldUsageError
from logsearch.query import LEVELS, LogQuery, QueryError


@pytest.fixture
def q(app) -> LogQuery:
    return LogQuery(FieldMap(app))


@pytest.fixture
def audit_q(audit) -> LogQuery:
    return LogQuery(FieldMap(audit))


def test_an_empty_query_is_still_a_valid_body(q):
    body = q.body()
    assert body["query"] == {"match_all": {}}
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}, {"event.id": {"order": "asc"}}]
    assert body["track_total_hits"] == 10_000
    assert "aggs" not in body


def test_everything_unscored_lands_in_filter_context(q):
    body = q.window("now-15m").service("checkout-api").term("log.level", "error").body()
    boolean = body["query"]["bool"]
    assert len(boolean["filter"]) == 3
    assert "must" not in boolean
    assert "must_not" not in boolean


def test_the_only_scored_clause_is_the_message_match(q):
    body = q.service("checkout-api").message("connection reset").body()
    boolean = body["query"]["bool"]
    assert boolean["must"] == [{"match": {"message": {"query": "connection reset"}}}]
    assert boolean["filter"] == [{"terms": {"service.name": ["checkout-api"]}}]


def test_level_at_least_is_a_terms_clause_in_severity_order(q):
    body = q.level_at_least("warn").body()
    assert body["query"]["bool"]["filter"] == [{"terms": {"log.level": ["warn", "error", "fatal"]}}]
    assert LEVELS.index("error") > LEVELS.index("warn")
    # The reason, stated where a reader will meet it.
    assert "sorts error below info" in q.notes()[0]


def test_the_range_version_of_the_same_question_is_refused(q):
    """Because sorted as bytes, 'error' < 'info' < 'warn'."""
    assert sorted(["warn", "error", "info"]) == ["error", "info", "warn"]
    with pytest.raises(FieldUsageError, match="gte: 'warn' excludes 'error'"):
        q.range("log.level", gte="warn")


def test_an_unknown_level_is_refused_before_a_clause_is_built(q):
    with pytest.raises(QueryError, match="not one of trace, debug"):
        q.level_at_least("critical")
    assert q.body()["query"] == {"match_all": {}}


def test_a_term_on_the_text_half_is_refused_and_names_the_keyword(q):
    with pytest.raises(FieldUsageError, match=r"Use message\.raw"):
        q.term("message", "Timeout")
    assert q.term("message.raw", "Timeout").body()["query"]["bool"]["filter"] == [
        {"term": {"message.raw": "Timeout"}}
    ]


def test_an_aggregation_on_text_is_rewritten_onto_the_keyword(q):
    body = q.count_by("message", size=5).body()
    assert body["aggs"]["by_message"]["terms"]["field"] == "message.raw"


def test_terms_aggregations_write_their_shard_size_down(q):
    body = q.count_by("service.name", size=20).body()
    terms = body["aggs"]["by_service_name"]["terms"]
    # Elasticsearch's own default, made visible rather than implied.
    assert terms["shard_size"] == int(20 * 1.5) + 10 == 40
    assert terms["size"] == 20


def test_an_empty_terms_list_is_refused(q):
    with pytest.raises(QueryError, match="matches nothing"):
        q.terms("service.name", [])


def test_a_range_needs_a_bound(q):
    with pytest.raises(QueryError, match="at least one bound"):
        q.range("event.duration_ms")
    assert q.range("event.duration_ms", gte=100, lte=500).body()["query"]["bool"]["filter"] == [
        {"range": {"event.duration_ms": {"gte": 100, "lte": 500}}}
    ]


def test_the_time_window_carries_an_explicit_format(q):
    clause = q.window("2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z", time_zone="+05:00")
    bounds = clause.body()["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert bounds["format"] == "strict_date_optional_time||epoch_millis"
    assert bounds["time_zone"] == "+05:00"


def test_a_phrase_on_a_field_without_positions_is_refused(q):
    with pytest.raises(FieldUsageError, match="stores no "):
        q.phrase("at pay.Charge", field="error.stack_trace")
    assert q.phrase("connection reset").body()["query"]["bool"]["must"] == [
        {"match_phrase": {"message": "connection reset"}}
    ]


def test_labels_resolve_on_the_app_mapping_and_not_on_the_audit_one(q, audit_q):
    assert q.label("tenant", "acme").body()["query"]["bool"]["filter"] == [
        {"term": {"labels.tenant": "acme"}}
    ]
    with pytest.raises(FieldUsageError, match="not in the logs-audit mapping"):
        audit_q.label("tenant", "acme")


def test_the_audit_mapping_answers_its_own_fields(audit_q):
    body = audit_q.term("user.id", "u-3").count_by("event.action").body()
    assert body["query"]["bool"]["filter"] == [{"term": {"user.id": "u-3"}}]
    assert body["aggs"]["by_event_action"]["terms"]["field"] == "event.action"


def test_finding_what_ignore_malformed_dropped(q):
    body = q.with_dropped_fields("event.duration_ms").body()
    assert body["query"]["bool"]["filter"] == [{"term": {"_ignored": "event.duration_ms"}}]
    assert "never the value" in q.notes()[0]
    any_dropped = LogQuery(q.field_map).with_dropped_fields().body()
    assert any_dropped["query"]["bool"]["filter"] == [{"exists": {"field": "_ignored"}}]


def test_a_page_past_max_result_window_is_refused_with_the_alternative(q):
    assert q.field_map.composed.settings["index.max_result_window"] == 10_000
    with pytest.raises(QueryError, match="past index.max_result_window"):
        q.page(10_001)
    assert q.page(500).body()["size"] == 500


def test_search_after_needs_one_value_per_sort_key(q):
    with pytest.raises(QueryError, match="2 sort keys, 1 values"):
        q.after(["2026-03-01T00:00:00Z"]).body()
    resumed = LogQuery(q.field_map).after(["2026-03-01T00:00:00Z", "e-0012"]).body()
    assert resumed["search_after"] == ["2026-03-01T00:00:00Z", "e-0012"]


def test_the_tiebreaker_is_added_once_and_only_once(q):
    body = q.sort_by("@timestamp", "desc").sort_by("event.id", "asc").body()
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}, {"event.id": {"order": "asc"}}]


def test_a_histogram_keeps_its_empty_buckets(q):
    histogram = q.over_time("30s").body()["aggs"]["over_time"]["date_histogram"]
    assert histogram["min_doc_count"] == 0
    assert histogram["fixed_interval"] == "30s"


def test_percentiles_refuse_a_field_that_is_not_numeric(q):
    with pytest.raises(QueryError, match="percentiles need a numeric field"):
        q.percentiles("log.level")
    body = q.percentiles("event.duration_ms", percents=(50, 99)).body()
    assert body["aggs"]["event_duration_ms_percentiles"]["percentiles"]["percents"] == [50, 99]


def test_cardinality_says_it_is_an_estimate(q):
    body = q.distinct("trace.id").body()
    assert body["aggs"]["distinct_trace_id"] == {"cardinality": {"field": "trace.id"}}
    assert "HyperLogLog" in q.notes()[0]


def test_source_filtering_refuses_a_field_nobody_mapped(q):
    with pytest.raises(FieldUsageError, match="not in the logs-app mapping"):
        q.source("@timestamp", "user.email")
    assert q.source("@timestamp", "labels.tenant").body()["_source"] == {
        "includes": ["@timestamp", "labels.tenant"]
    }


def test_counting_every_hit_is_opt_in(q):
    assert q.body()["track_total_hits"] == 10_000
    assert q.total_hits(True).body()["track_total_hits"] is True


def test_must_not_is_separate_from_filter(q):
    body = q.service("search-api").without("log.level", "debug").body()
    assert body["query"]["bool"]["must_not"] == [{"term": {"log.level": "debug"}}]
    assert body["query"]["bool"]["filter"] == [{"terms": {"service.name": ["search-api"]}}]
