from __future__ import annotations

import pytest

from logsearch.fields import FieldMap, FieldUsageError


@pytest.fixture(scope="module")
def app_fields(app) -> FieldMap:
    return FieldMap(app)


@pytest.fixture(scope="module")
def audit_fields(audit) -> FieldMap:
    return FieldMap(audit)


def test_counts_leaves_objects_and_multi_fields(app_fields):
    counted = app_fields.total_fields_count
    assert counted == len(app_fields.fields)
    kinds = {f.kind for f in app_fields}
    assert kinds == {"object", "leaf", "multi"}
    # The three multi-fields are counted, which is the half of the rule that is
    # easy to get wrong: they are extra entries in the mapping, not free.
    assert sorted(f.path for f in app_fields if f.kind == "multi") == [
        "error.message.raw",
        "message.raw",
        "url.path.text",
    ]


def test_the_composed_mapping_fits_inside_the_declared_limit(app_fields, audit_fields):
    assert app_fields.total_fields_count == 55
    assert audit_fields.total_fields_count == 43
    assert app_fields.composed.total_fields_limit == 200
    assert app_fields.headroom == 145
    assert audit_fields.headroom == 157


def test_text_is_searchable_and_not_aggregatable(app_fields):
    message = app_fields.get("message")
    assert message.searchable is True
    assert message.aggregatable is False
    raw = app_fields.get("message.raw")
    assert raw.aggregatable is True
    assert raw.ignore_above == 1024


def test_index_false_keeps_doc_values(app_fields):
    """url.query can be grouped and cannot be filtered. That is deliberate."""
    query = app_fields.get("url.query")
    assert query.searchable is False
    assert query.aggregatable is True
    with pytest.raises(FieldUsageError, match="index: false"):
        app_fields.resolve("url.query", "term")
    assert app_fields.resolve("url.query", "agg") == "url.query"


def test_objects_are_counted_and_cannot_be_queried(app_fields):
    http = app_fields.get("http")
    assert http.kind == "object"
    assert http.searchable is False
    with pytest.raises(FieldUsageError, match="is an object, not a field"):
        app_fields.resolve("http", "term")


def test_term_on_a_text_field_is_refused_with_the_multi_field_named(app_fields):
    with pytest.raises(FieldUsageError, match=r"Use message\.raw for an exact match"):
        app_fields.resolve("message", "term")


def test_aggregating_a_text_field_routes_to_its_keyword(app_fields):
    assert app_fields.resolve("message", "agg") == "message.raw"
    assert app_fields.resolve("url.path.text", "agg") == "url.path"


def test_text_with_no_keyword_sibling_cannot_be_aggregated(app_fields):
    with pytest.raises(FieldUsageError, match="no keyword multi-field"):
        app_fields.resolve("error.stack_trace", "agg")


def test_phrase_query_is_refused_where_positions_were_not_stored(app_fields):
    """error.stack_trace is index_options: docs, so phrases silently miss."""
    assert app_fields.resolve("error.stack_trace", "match") == "error.stack_trace"
    with pytest.raises(FieldUsageError, match="stores no "):
        app_fields.resolve("error.stack_trace", "match_phrase")
    assert app_fields.resolve("message", "match_phrase") == "message"


def test_range_on_a_keyword_is_refused_with_the_reason(app_fields):
    with pytest.raises(FieldUsageError, match="gte: 'warn' excludes 'error'"):
        app_fields.resolve("log.level", "range")
    assert app_fields.resolve("http.response.status_code", "range")
    assert app_fields.resolve("@timestamp", "range") == "@timestamp"
    assert app_fields.resolve("client.ip", "range") == "client.ip"


def test_flattened_keys_resolve_for_terms_and_refuse_ranges(app_fields):
    assert app_fields.flattened_roots() == ["labels"]
    assert app_fields.within_flattened("labels.tenant") == "labels"
    assert app_fields.resolve("labels.tenant", "term") == "labels.tenant"
    with pytest.raises(FieldUsageError, match="indexed as a keyword"):
        app_fields.resolve("labels.retry_count", "range")


def test_an_unmapped_field_is_refused_with_the_200_warning(app_fields):
    with pytest.raises(FieldUsageError, match="matches nothing and returns 200"):
        app_fields.resolve("user.email", "term")


def test_the_audit_mapping_has_no_labels_at_all(audit_fields):
    assert audit_fields.flattened_roots() == []
    with pytest.raises(FieldUsageError, match="not in the logs-audit mapping"):
        audit_fields.resolve("labels.tenant", "term")
    assert audit_fields.resolve("user.id", "term") == "user.id"


def test_nothing_in_the_shipped_mappings_ignores_malformed_values(app_fields, audit_fields):
    for field_map in (app_fields, audit_fields):
        offenders = [f.path for f in field_map if f.ignore_malformed]
        assert offenders == []


def test_the_lenient_variant_turns_ignore_malformed_on_for_every_field(templates):
    lenient = FieldMap(templates.compose("logs-app-lenient"))
    typed = [f for f in lenient if f.kind != "object"]
    assert typed and all(f.ignore_malformed for f in typed)
