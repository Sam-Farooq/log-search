"""Checks over the files in `indices/`, run before anything is installed.

Each one is a mistake that a cluster accepts. A template with a typo in
`composed_of` is the exception: Elasticsearch refuses that one. Everything else
here installs cleanly and goes wrong later, which is the reason to check it in
a pull request instead.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from enum import StrEnum

from logsearch.conflicts import unknown_date_formats
from logsearch.fields import FieldMap, FieldUsageError
from logsearch.lifecycle import LifecycleError, Policy
from logsearch.query import DEFAULT_SOURCE, LogQuery
from logsearch.templates import TemplateError, TemplateSet


class Level(StrEnum):
    ERROR = "error"
    NOTE = "note"


@dataclass(frozen=True)
class Finding:
    level: Level
    code: str
    subject: str
    message: str

    def __str__(self) -> str:
        return f"{self.level.value.upper():<5} {self.code:<22} {self.subject}: {self.message}"


def lint(templates: TemplateSet) -> list[Finding]:
    findings: list[Finding] = []
    for check in (
        _composition,
        _field_budget,
        _dynamic_and_catch_all,
        _ignore_malformed,
        _date_formats,
        _builder_fields,
        _unaggregatable_text,
        _pattern_overlap,
        _policies,
        _bootstrap,
    ):
        findings.extend(check(templates))
    return findings


def _composed(templates: TemplateSet, name: str):
    return templates.compose(name)


def _composition(templates: TemplateSet) -> list[Finding]:
    findings = []
    for name in sorted(templates.index_templates):
        try:
            templates.compose(name)
        except TemplateError as exc:
            findings.append(Finding(Level.ERROR, "composition", name, str(exc)))
    return findings


def _installed(templates: TemplateSet):
    for template in templates.installed_templates():
        try:
            yield template, FieldMap(templates.compose(template.name))
        except TemplateError:
            continue


def _field_budget(templates: TemplateSet) -> list[Finding]:
    findings = []
    for template, field_map in _installed(templates):
        count = field_map.total_fields_count
        limit = field_map.composed.total_fields_limit
        if count >= limit:
            findings.append(
                Finding(
                    Level.ERROR,
                    "total_fields",
                    template.name,
                    f"{count} fields against a limit of {limit}. The next field added to a "
                    f"component breaks every write with an illegal_argument_exception",
                )
            )
        else:
            findings.append(
                Finding(
                    Level.NOTE,
                    "total_fields",
                    template.name,
                    f"{count} fields of {limit}, {limit - count} spare, counting leaf "
                    f"fields, object nodes and multi-fields",
                )
            )
    return findings


def _dynamic_and_catch_all(templates: TemplateSet) -> list[Finding]:
    findings = []
    for template, field_map in _installed(templates):
        dynamic = field_map.composed.dynamic
        if dynamic == "true":
            findings.append(
                Finding(
                    Level.ERROR,
                    "dynamic",
                    template.name,
                    "dynamic is true, so any key that arrives is added to the mapping and "
                    "counts against total_fields.limit from then on. One request body with "
                    "generated keys is a mapping explosion",
                )
            )
        declared = template.meta.get("catch_all", None)
        roots = field_map.flattened_roots()
        if declared is None:
            findings.append(
                Finding(
                    Level.ERROR,
                    "catch_all",
                    template.name,
                    "_meta.catch_all is missing. Say which flattened field holds unknown "
                    "keys, or false to mean the field set is closed",
                )
            )
        elif declared is False:
            if roots:
                findings.append(
                    Finding(
                        Level.ERROR,
                        "catch_all",
                        template.name,
                        f"_meta.catch_all is false and the mapping has {', '.join(roots)}",
                    )
                )
            elif dynamic != "strict":
                findings.append(
                    Finding(
                        Level.ERROR,
                        "catch_all",
                        template.name,
                        f"no catch-all and dynamic is {dynamic}, so an unknown key is kept "
                        f"in _source and silently unsearchable. With no catch-all the only "
                        f"honest setting is strict, which rejects the write",
                    )
                )
        elif declared not in roots:
            findings.append(
                Finding(
                    Level.ERROR,
                    "catch_all",
                    template.name,
                    f"_meta.catch_all is {declared!r}, which is not a flattened field in "
                    f"the composed mapping",
                )
            )
    return findings


def _ignore_malformed(templates: TemplateSet) -> list[Finding]:
    findings = []
    for template, field_map in _installed(templates):
        allowed = bool(template.meta.get("allow_ignore_malformed", False))
        if field_map.composed.index_ignore_malformed and not allowed:
            findings.append(
                Finding(
                    Level.ERROR,
                    "ignore_malformed",
                    template.name,
                    "index.mapping.ignore_malformed is true, so every field in the index "
                    "drops a value it cannot parse and the write still returns a 201",
                )
            )
        offenders = sorted(f.path for f in field_map if f.ignore_malformed)
        if offenders and not allowed:
            findings.append(
                Finding(
                    Level.ERROR,
                    "ignore_malformed",
                    template.name,
                    f"{', '.join(offenders)} set ignore_malformed with _meta."
                    f"allow_ignore_malformed false. A dropped field with a successful "
                    f"response is the one failure nobody goes looking for",
                )
            )
    return findings


def _date_formats(templates: TemplateSet) -> list[Finding]:
    findings = []
    for template, field_map in _installed(templates):
        for field in field_map:
            if field.type not in {"date", "date_nanos"}:
                continue
            declared = field_map.definition(field.path).get("format")
            unknown = unknown_date_formats(declared)
            if unknown:
                findings.append(
                    Finding(
                        Level.ERROR,
                        "date_format",
                        template.name,
                        f"{field.path} declares {', '.join(unknown)}, which this repo's "
                        f"value checker does not model, so every verdict about that field "
                        f"would be a guess",
                    )
                )
    return findings


def _builder_fields(templates: TemplateSet) -> list[Finding]:
    """Every field the query builder names by default has to exist.

    A query naming an unmapped field is not an error. It matches nothing and
    returns 200, which reads as an empty result set rather than as a bug.
    """
    findings = []
    for template, field_map in _installed(templates):
        query = LogQuery(field_map)
        wanted: list[tuple[str, str]] = [
            (query.time_field, "range"),
            (query.time_field, "agg"),
            (query.tiebreaker, "sort"),
            ("log.level", "term"),
            ("message", "match"),
        ]
        wanted += [(path, "exists") for path in DEFAULT_SOURCE]
        for path, intent in wanted:
            try:
                field_map.resolve(path, intent)  # type: ignore[arg-type]
            except FieldUsageError as exc:
                findings.append(
                    Finding(Level.ERROR, "builder_field", template.name, f"{intent}: {exc}")
                )
    return findings


def _unaggregatable_text(templates: TemplateSet) -> list[Finding]:
    findings = []
    for template, field_map in _installed(templates):
        for field in field_map:
            if field.is_text and field_map.aggregatable_sibling(field.path) is None:
                findings.append(
                    Finding(
                        Level.NOTE,
                        "no_keyword_sibling",
                        template.name,
                        f"{field.path} is {field.type} with no keyword multi-field, so it "
                        f"can be searched and never grouped. Deliberate here: a stack "
                        f"trace is not a facet",
                    )
                )
    return findings


def _pattern_overlap(templates: TemplateSet) -> list[Finding]:
    """Two templates matching one index name is only safe at different priorities."""
    findings = []
    installed = templates.installed_templates()
    for i, first in enumerate(installed):
        for second in installed[i + 1 :]:
            if first.priority != second.priority:
                continue
            clash = [
                (a, b)
                for a in first.index_patterns
                for b in second.index_patterns
                if fnmatch.fnmatch(a.replace("*", "zzz"), b)
                or fnmatch.fnmatch(b.replace("*", "zzz"), a)
            ]
            if clash:
                findings.append(
                    Finding(
                        Level.ERROR,
                        "pattern_overlap",
                        f"{first.name} and {second.name}",
                        f"both match {clash[0][0]} at priority {first.priority}. "
                        f"Elasticsearch refuses the second PUT",
                    )
                )
    for template in templates.index_templates.values():
        if template.installed:
            continue
        beaten = [
            other.name
            for other in installed
            if other.priority < template.priority
            and any(a == b for a in template.index_patterns for b in other.index_patterns)
        ]
        if beaten:
            findings.append(
                Finding(
                    Level.NOTE,
                    "uninstalled_wins",
                    template.name,
                    f"not installed, and its priority {template.priority} is above "
                    f"{', '.join(beaten)}. Installing it would take over those patterns at "
                    f"the next rollover without an error",
                )
            )
    return findings


def _policies(templates: TemplateSet) -> list[Finding]:
    findings = []
    for template, _ in _installed(templates):
        name = template.policy_name
        alias = template.write_alias
        if name is None:
            findings.append(
                Finding(
                    Level.ERROR,
                    "lifecycle",
                    template.name,
                    "index.lifecycle.name is unset, so indices from this template have no "
                    "policy and nothing rolls or expires. The PUT succeeds either way",
                )
            )
            continue
        if name not in templates.policies:
            findings.append(
                Finding(
                    Level.ERROR,
                    "lifecycle",
                    template.name,
                    f"names policy {name!r}, and there is no ilm-{name}.json. A template "
                    f"referencing a policy that does not exist installs without complaint",
                )
            )
            continue
        try:
            policy = Policy.load(name, templates.policies[name])
        except LifecycleError as exc:
            findings.append(Finding(Level.ERROR, "lifecycle", name, str(exc)))
            continue
        if alias is None:
            findings.append(
                Finding(
                    Level.ERROR,
                    "rollover_alias",
                    template.name,
                    "index.lifecycle.rollover_alias is unset, so the rollover action has "
                    "nothing to move and ILM stops on that step",
                )
            )
        elif policy.write_alias != alias:
            findings.append(
                Finding(
                    Level.ERROR,
                    "rollover_alias",
                    template.name,
                    f"template writes through {alias!r} and ilm-{name}.json records "
                    f"{policy.write_alias!r}",
                )
            )
        if not policy.rollover:
            findings.append(
                Finding(
                    Level.ERROR,
                    "rollover",
                    name,
                    "the hot phase has no rollover action, so one index grows until the "
                    "delete phase removes all of it at once",
                )
            )
        hot = policy.phase("hot")
        if hot and "forcemerge" in hot.actions and "rollover" not in hot.actions:
            findings.append(
                Finding(
                    Level.ERROR,
                    "forcemerge",
                    name,
                    "forcemerge in hot with no rollover merges the index that is still "
                    "being written to",
                )
            )
        for problem in policy.out_of_order_phases():
            findings.append(Finding(Level.ERROR, "phase_order", name, problem))
        try:
            ceiling = policy.ceiling(
                primaries=int(template.settings.get("index.number_of_shards", 1) or 1),
                replicas=int(
                    FieldMap(templates.compose(template.name)).composed.settings.get(
                        "index.number_of_replicas", 1
                    )
                ),
            )
        except LifecycleError as exc:
            findings.append(Finding(Level.ERROR, "ceiling", name, str(exc)))
        else:
            findings.append(Finding(Level.NOTE, "ceiling", name, str(ceiling)))
    return findings


def _bootstrap(templates: TemplateSet) -> list[Finding]:
    findings = []
    try:
        steps = templates.bootstrap_steps
    except TemplateError as exc:
        return [Finding(Level.ERROR, "bootstrap", "bootstrap-order.json", str(exc))]

    order = {"ilm_policy": 0, "component_template": 1, "index_template": 2, "write_index": 3}
    seen = -1
    for step in steps:
        rank = order.get(str(step.get("kind")), -1)
        if rank < 0:
            findings.append(
                Finding(
                    Level.ERROR,
                    "bootstrap",
                    str(step.get("name")),
                    f"unknown kind {step.get('kind')!r}",
                )
            )
            continue
        if rank < seen:
            findings.append(
                Finding(
                    Level.ERROR,
                    "bootstrap_order",
                    str(step.get("name")),
                    f"a {step['kind']} step comes after a later kind. A composed template "
                    f"PUT before its components is rejected",
                )
            )
        seen = max(seen, rank)

    referenced = {str(step["file"]) for step in steps if "file" in step}
    for template in templates.installed_templates():
        if template.path.name not in referenced:
            findings.append(
                Finding(
                    Level.ERROR,
                    "bootstrap",
                    template.name,
                    "is marked installed and is not in bootstrap-order.json",
                )
            )
    for name, template in templates.index_templates.items():
        if not template.installed and template.path.name in referenced:
            findings.append(
                Finding(
                    Level.ERROR,
                    "bootstrap",
                    name,
                    "is marked not installed and is in the bootstrap order",
                )
            )

    aliases = {t.write_alias: t for t in templates.installed_templates()}
    for step in steps:
        if step.get("kind") != "write_index":
            continue
        alias = str(step.get("alias"))
        index = str(step.get("name"))
        template = aliases.get(alias)
        if template is None:
            findings.append(
                Finding(
                    Level.ERROR,
                    "write_index",
                    index,
                    f"alias {alias!r} is not the rollover_alias of any installed template",
                )
            )
        elif not any(fnmatch.fnmatch(index, pattern) for pattern in template.index_patterns):
            findings.append(
                Finding(
                    Level.ERROR,
                    "write_index",
                    index,
                    f"does not match {', '.join(template.index_patterns)}, so it is created "
                    f"with none of that template's settings or mappings",
                )
            )
    return findings


def errors(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.level is Level.ERROR]
