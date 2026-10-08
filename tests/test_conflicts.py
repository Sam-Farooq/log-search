from __future__ import annotations

import json
from pathlib import Path

import pytest

from logsearch.conflicts import KNOWN_DATE_FORMATS, Verdict, check_value, unknown_date_formats
from logsearch.fields import FieldMap

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CASES = json.loads((FIXTURES / "type-cases.json").read_text(encoding="utf-8"))["cases"]


@pytest.fixture(scope="module")
def app_fields(app) -> FieldMap:
    return FieldMap(app)


def check(app_fields: FieldMap, path: str, value):
    field = app_fields.get(path)
    assert field is not None, path
    return check_value(value, field, app_fields.definition(path))


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c['field']}={c['value']!r}")
def test_the_shared_type_table(app_fields, case):
    """The same rows the live test replays against a cluster."""
    result = check(app_fields, case["field"], case["value"])
    assert result.verdict.value == case["verdict"], result.reason


def test_every_case_in_the_table_is_reachable(app_fields):
    verdicts = {case["verdict"] for case in CASES}
    assert verdicts == {"ok", "coerced", "malformed", "shape"}


def test_a_duration_with_a_unit_carries_the_repair_it_cannot_apply(app_fields):
    result = check(app_fields, "event.duration_ms", "1.4s")
    assert result.verdict is Verdict.MALFORMED
    assert result.normalized == 1400
    assert "duration with a unit" in result.reason
    assert check(app_fields, "event.duration_ms", "250ms").normalized == 250
    assert check(app_fields, "event.duration_ms", "2m").normalized == 120000


def test_an_unparseable_string_carries_no_repair(app_fields):
    result = check(app_fields, "event.duration_ms", "soon")
    assert result.verdict is Verdict.MALFORMED
    assert result.normalized is None


def test_a_fractional_value_does_not_fit_an_integer_field(app_fields):
    assert check(app_fields, "event.duration_ms", 12.5).verdict is Verdict.MALFORMED
    truncated = check(app_fields, "event.duration_ms", 12.0)
    assert truncated.verdict is Verdict.COERCED
    assert truncated.normalized == 12


def test_the_short_bound_is_the_reason_a_status_code_fails(app_fields):
    assert check(app_fields, "event.duration_ms", 70000).verdict is Verdict.OK
    out_of_range = check(app_fields, "http.response.status_code", 70000)
    assert out_of_range.verdict is Verdict.MALFORMED
    assert "-32768 to 32767" in out_of_range.reason


def test_an_object_for_a_scalar_names_ignore_malformed_as_no_help(app_fields):
    result = check(app_fields, "event.duration_ms", {"value": 1, "unit": "ms"})
    assert result.verdict is Verdict.SHAPE
    assert "ignore_malformed does not cover this case" in result.reason


def test_null_is_skipped_rather_than_indexed(app_fields):
    assert check(app_fields, "event.duration_ms", None).verdict is Verdict.OK
    assert check(app_fields, "log.level", None).normalized is None


def test_an_array_takes_the_worst_verdict_in_it(app_fields):
    assert check(app_fields, "tags", ["a", "b"]).verdict is Verdict.OK
    mixed = check(app_fields, "event.duration_ms", [10, "nope", 20])
    assert mixed.verdict is Verdict.MALFORMED


def test_a_keyword_past_ignore_above_is_a_loss_and_not_an_error(app_fields):
    result = check(app_fields, "message.raw", "x" * 1100)
    assert result.verdict is Verdict.OVER_IGNORE_ABOVE
    assert "1100 characters against ignore_above 1024" in result.reason
    assert result.normalized == "x" * 1100


def test_flattened_depth_limit_comes_from_the_file(app_fields):
    assert app_fields.definition("labels")["depth_limit"] == 3
    assert check(app_fields, "labels", {"a": {"b": "c"}}).verdict is Verdict.OK
    too_deep = check(app_fields, "labels", {"a": {"b": {"c": {"d": "e"}}}})
    assert too_deep.verdict is Verdict.MALFORMED
    assert "depth_limit 3" in too_deep.reason


def test_a_long_flattened_value_is_dropped_per_key(app_fields):
    result = check(app_fields, "labels", {"blob": "y" * 300})
    assert result.verdict is Verdict.OVER_IGNORE_ABOVE
    assert "labels.blob" in result.reason


def test_the_date_formats_this_model_can_judge(app_fields):
    assert unknown_date_formats("strict_date_optional_time||epoch_millis") == []
    assert unknown_date_formats("yyyy-MM-dd HH:mm:ss Z") == ["yyyy-MM-dd HH:mm:ss Z"]
    assert "epoch_second" in KNOWN_DATE_FORMATS


def test_every_date_field_in_the_shipped_templates_uses_a_format_we_model(templates):
    for name in ("logs-app", "logs-audit"):
        field_map = FieldMap(templates.compose(name))
        for field in field_map:
            if field.type in {"date", "date_nanos"}:
                declared = field_map.definition(field.path).get("format")
                assert unknown_date_formats(declared) == [], f"{name}:{field.path}"
