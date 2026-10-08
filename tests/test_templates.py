from __future__ import annotations

import json

import pytest

from logsearch.templates import TemplateError, TemplateSet, flatten_settings


def test_every_file_in_indices_is_loaded(templates, indices_dir):
    """A file nobody reads is a file nobody checks."""
    on_disk = {p.name for p in indices_dir.glob("*.json")}
    loaded = (
        {c.path.name for c in templates.components.values()}
        | {t.path.name for t in templates.index_templates.values()}
        | {f"ilm-{name}.json" for name in templates.policies}
        | {"bootstrap-order.json"}
    )
    assert on_disk == loaded


def test_flatten_settings_matches_the_stored_shape():
    nested = {"index": {"mapping": {"total_fields": {"limit": 200}}, "number_of_shards": 1}}
    assert flatten_settings(nested) == {
        "index.mapping.total_fields.limit": 200,
        "index.number_of_shards": 1,
    }


def test_app_template_composes_four_components(templates, app):
    template = templates.index_templates["logs-app"]
    assert template.composed_of == ["logs-settings", "logs-base", "logs-http", "logs-labels"]
    props = app.properties()
    # One field from each component, so the merge is proven end to end.
    assert props["@timestamp"]["type"] == "date"
    assert props["http"]["properties"]["response"]["properties"]["status_code"]["type"] == "short"
    assert props["labels"]["type"] == "flattened"
    assert app.settings["index.number_of_shards"] == 1


def test_the_index_template_wins_over_its_components(templates, audit):
    """`event` is defined in logs-base and extended by the audit template."""
    event = audit.properties()["event"]["properties"]
    assert set(event) >= {"id", "dataset", "duration_ms", "action", "category"}
    assert audit.sources["event.id"] == "logs-base"
    assert audit.sources["event.action"] == "template:logs-audit"


def test_audit_has_no_catch_all(audit):
    assert "labels" not in audit.properties()
    assert audit.dynamic == "strict"
    assert audit.meta["allow_ignore_malformed"] is False


def test_audit_overrides_the_shared_refresh_interval(templates, audit, app):
    assert app.settings["index.refresh_interval"] == "10s"
    assert audit.settings["index.refresh_interval"] == "30s"


def test_lenient_variant_is_marked_not_installed(templates):
    lenient = templates.index_templates["logs-app-lenient"]
    assert lenient.installed is False
    assert lenient.priority > templates.index_templates["logs-app"].priority
    composed = templates.compose("logs-app-lenient")
    assert composed.index_ignore_malformed is True
    assert composed.dynamic == "false"
    assert [t.name for t in templates.installed_templates()] == ["logs-app", "logs-audit"]


def test_missing_component_is_refused_by_name(write_indices):
    directory = write_indices(
        {
            "template-x.json": {
                "index_patterns": ["x-*"],
                "composed_of": ["nope"],
                "template": {"mappings": {}},
            }
        }
    )
    with pytest.raises(TemplateError, match="composed_of names 'nope'"):
        TemplateSet(directory).compose("x")


def test_two_components_disagreeing_about_a_type_is_refused(write_indices):
    base = {"template": {"mappings": {"properties": {"port": {"type": "integer"}}}}}
    other = {"template": {"mappings": {"properties": {"port": {"type": "keyword"}}}}}
    directory = write_indices(
        {
            "component-a.json": base,
            "component-b.json": other,
            "template-t.json": {
                "index_patterns": ["t-*"],
                "composed_of": ["a", "b"],
                "template": {},
            },
        }
    )
    with pytest.raises(TemplateError, match="port is keyword here and integer in a"):
        TemplateSet(directory).compose("t")


def test_unparseable_file_names_the_line(tmp_path):
    directory = tmp_path / "indices"
    directory.mkdir()
    (directory / "component-broken.json").write_text('{\n  "template": {,}\n}', encoding="utf-8")
    with pytest.raises(TemplateError, match="line 2"):
        TemplateSet(directory)


def test_compose_lists_known_templates_when_asked_for_a_missing_one(templates):
    with pytest.raises(TemplateError, match="Known: logs-app, logs-app-lenient, logs-audit"):
        templates.compose("logs-nope")


def test_bootstrap_order_puts_policies_and_components_before_templates(templates):
    kinds = [step["kind"] for step in templates.bootstrap_steps]
    assert kinds.index("ilm_policy") < kinds.index("component_template")
    assert kinds.index("component_template") < kinds.index("index_template")
    assert kinds.index("index_template") < kinds.index("write_index")


def test_bootstrap_references_every_installed_file_and_nothing_else(templates, indices_dir):
    referenced = {step["file"] for step in templates.bootstrap_steps if "file" in step}
    expected = {
        p.name
        for p in indices_dir.glob("*.json")
        if p.name != "bootstrap-order.json"
        and json.loads(p.read_text(encoding="utf-8")).get("_meta", {}).get("installed", True)
    }
    assert referenced == expected
