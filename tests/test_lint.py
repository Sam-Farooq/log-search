from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from logsearch.lint import Level, errors, lint
from logsearch.templates import TemplateSet

INDICES = Path(__file__).resolve().parent.parent / "indices"


def test_the_shipped_templates_have_no_errors(templates):
    findings = lint(templates)
    assert errors(findings) == []
    assert {f.code for f in findings} == {
        "total_fields",
        "no_keyword_sibling",
        "uninstalled_wins",
        "ceiling",
    }
    assert all(f.level is Level.NOTE for f in findings)


def test_the_finding_codes_are_the_set_the_readme_counts():
    """Nineteen, and the README says nineteen. One of the two had to be a test."""
    import ast

    tree = ast.parse((Path(__file__).resolve().parent.parent / "logsearch" / "lint.py").read_text())
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Finding":
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                found.add(node.args[1].value)
            for keyword in node.keywords:
                if keyword.arg == "code" and isinstance(keyword.value, ast.Constant):
                    found.add(keyword.value.value)
    assert len(found) == 19
    assert found == {
        "bootstrap",
        "bootstrap_order",
        "builder_field",
        "catch_all",
        "ceiling",
        "composition",
        "date_format",
        "dynamic",
        "forcemerge",
        "ignore_malformed",
        "lifecycle",
        "no_keyword_sibling",
        "pattern_overlap",
        "phase_order",
        "rollover",
        "rollover_alias",
        "total_fields",
        "uninstalled_wins",
        "write_index",
    }
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text()
    assert "Nineteen finding codes" in readme


def test_the_notes_carry_the_numbers_a_reader_came_for(templates):
    findings = {(f.code, f.subject): f.message for f in lint(templates)}
    assert "55 fields of 200, 145 spare" in findings[("total_fields", "logs-app")]
    assert "31 live indices at 30gb" in findings[("ceiling", "logs-app")]
    assert "1080gb of primaries" in findings[("ceiling", "logs-audit")]


@pytest.fixture
def copied(tmp_path: Path):
    """The real `indices/` directory, copied so a test can break one file."""

    def _copy(edits: dict[str, Any] | None = None, drop: list[str] | None = None) -> TemplateSet:
        directory = tmp_path / "indices"
        directory.mkdir(exist_ok=True)
        for source in INDICES.glob("*.json"):
            if drop and source.name in drop:
                continue
            body = json.loads(source.read_text(encoding="utf-8"))
            if edits and source.name in edits:
                body = _deep_update(copy.deepcopy(body), edits[source.name])
            (directory / source.name).write_text(json.dumps(body, indent=2), encoding="utf-8")
        return TemplateSet(directory)

    return _copy


def _deep_update(target: dict, patch: dict) -> dict:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_update(target[key], value)
        else:
            target[key] = value
    return target


def codes(findings) -> set[str]:
    return {f.code for f in errors(findings)}


def test_dynamic_true_is_an_error(copied):
    broken = copied({"template-logs-app.json": {"template": {"mappings": {"dynamic": True}}}})
    findings = lint(broken)
    assert "dynamic" in codes(findings)
    assert any("mapping explosion" in f.message for f in errors(findings))


def test_a_catch_all_that_is_not_in_the_mapping_is_an_error(copied):
    broken = copied({"template-logs-audit.json": {"_meta": {"catch_all": "labels"}}})
    assert "catch_all" in codes(lint(broken))


def test_declaring_no_catch_all_while_having_one_is_an_error(copied):
    broken = copied({"template-logs-app.json": {"_meta": {"catch_all": False}}})
    assert "catch_all" in codes(lint(broken))


def test_no_catch_all_with_dynamic_false_is_an_error(copied):
    """The combination that loses a log line without saying anything."""
    broken = copied(
        {
            "template-logs-audit.json": {
                "template": {"mappings": {"dynamic": "false"}},
            }
        }
    )
    findings = errors(lint(broken))
    assert any("the only honest setting is strict" in f.message for f in findings)


def test_ignore_malformed_without_permission_is_an_error(copied):
    broken = copied(
        {
            "component-logs-base.json": {
                "template": {
                    "mappings": {
                        "properties": {
                            "event": {
                                "properties": {
                                    "duration_ms": {"type": "long", "ignore_malformed": True}
                                }
                            }
                        }
                    }
                }
            }
        }
    )
    findings = errors(lint(broken))
    assert "ignore_malformed" in {f.code for f in findings}
    assert any("nobody goes looking for" in f.message for f in findings)


def test_an_index_level_ignore_malformed_is_an_error(copied):
    broken = copied(
        {
            "component-logs-settings.json": {
                "template": {"settings": {"index": {"mapping": {"ignore_malformed": True}}}}
            }
        }
    )
    findings = errors(lint(broken))
    assert any("returns a 201" in f.message for f in findings)


def test_a_date_format_the_value_checker_cannot_model_is_an_error(copied):
    broken = copied(
        {
            "component-logs-base.json": {
                "template": {
                    "mappings": {
                        "properties": {
                            "@timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"}
                        }
                    }
                }
            }
        }
    )
    findings = errors(lint(broken))
    assert "date_format" in {f.code for f in findings}


def test_a_field_the_query_builder_needs_going_missing_is_an_error(copied):
    """event.id is the search_after tiebreaker. Remove it and paging breaks."""
    base = json.loads((INDICES / "component-logs-base.json").read_text(encoding="utf-8"))
    del base["template"]["mappings"]["properties"]["event"]["properties"]["id"]
    broken = copied()
    (broken.directory / "component-logs-base.json").write_text(json.dumps(base), encoding="utf-8")
    findings = errors(lint(TemplateSet(broken.directory)))
    assert "builder_field" in {f.code for f in findings}
    assert any("event.id" in f.message for f in findings)


def test_a_missing_ilm_file_is_an_error(copied):
    broken = copied(drop=["ilm-logs-app.json"])
    findings = errors(lint(broken))
    assert any("installs without complaint" in f.message for f in findings)


def test_a_rollover_alias_disagreeing_with_the_policy_is_an_error(copied):
    broken = copied(
        {"ilm-logs-app.json": {"policy": {"_meta": {"write_alias": "logs-application"}}}}
    )
    findings = errors(lint(broken))
    assert "rollover_alias" in {f.code for f in findings}


def _rewrite_policy(templates: TemplateSet, name: str, phases: dict) -> TemplateSet:
    """Replace a policy file outright.

    The patch helper merges dictionaries, which is wrong for `actions`: the
    point of these two cases is an action that is absent.
    """
    path = templates.directory / f"ilm-{name}.json"
    path.write_text(
        json.dumps({"policy": {"_meta": {"write_alias": name}, "phases": phases}}), "utf-8"
    )
    return TemplateSet(templates.directory)


def test_a_policy_with_no_rollover_is_an_error(copied):
    phases = {
        "hot": {"actions": {"set_priority": {"priority": 100}}},
        "delete": {"min_age": "30d", "actions": {"delete": {}}},
    }
    findings = errors(lint(_rewrite_policy(copied(), "logs-app", phases)))
    assert "rollover" in {f.code for f in findings}
    assert any("grows until the delete phase" in f.message for f in findings)


def test_forcemerge_in_hot_without_rollover_is_an_error(copied):
    phases = {
        "hot": {"actions": {"forcemerge": {"max_num_segments": 1}}},
        "delete": {"min_age": "30d", "actions": {"delete": {}}},
    }
    findings = errors(lint(_rewrite_policy(copied(), "logs-app", phases)))
    assert "forcemerge" in {f.code for f in findings}


def test_phases_out_of_order_are_an_error(copied):
    broken = copied({"ilm-logs-audit.json": {"policy": {"phases": {"cold": {"min_age": "5d"}}}}})
    findings = errors(lint(broken))
    assert "phase_order" in {f.code for f in findings}


def test_two_templates_matching_one_pattern_at_one_priority_is_an_error(copied):
    broken = copied(
        {"template-logs-app-lenient.json": {"_meta": {"installed": True}, "priority": 300}}
    )
    findings = errors(lint(broken))
    assert "pattern_overlap" in {f.code for f in findings}


def test_a_template_marked_installed_and_left_out_of_bootstrap_is_an_error(copied):
    broken = copied({"template-logs-app-lenient.json": {"_meta": {"installed": True}}})
    findings = errors(lint(broken))
    assert "bootstrap" in {f.code for f in findings}


def test_the_bootstrap_order_putting_a_template_before_its_components_is_an_error(copied):
    broken = copied()
    path = broken.directory / "bootstrap-order.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    body["steps"] = sorted(body["steps"], key=lambda s: s["kind"])
    path.write_text(json.dumps(body), encoding="utf-8")
    findings = errors(lint(TemplateSet(broken.directory)))
    assert "bootstrap_order" in {f.code for f in findings}


def test_a_write_index_that_matches_no_pattern_is_an_error(copied):
    broken = copied()
    path = broken.directory / "bootstrap-order.json"
    body = json.loads(path.read_text(encoding="utf-8"))
    for step in body["steps"]:
        if step["kind"] == "write_index" and step["alias"] == "logs-app":
            step["name"] = "logs_app_000001"
    path.write_text(json.dumps(body), encoding="utf-8")
    findings = errors(lint(TemplateSet(broken.directory)))
    assert "write_index" in {f.code for f in findings}
    assert any("none of that template's settings" in f.message for f in findings)


def test_a_field_count_over_the_limit_is_an_error(copied):
    broken = copied(
        {
            "component-logs-settings.json": {
                "template": {"settings": {"index": {"mapping": {"total_fields": {"limit": 40}}}}}
            }
        }
    )
    findings = errors(lint(broken))
    assert "total_fields" in {f.code for f in findings}
    assert any("illegal_argument_exception" in f.message for f in findings)
