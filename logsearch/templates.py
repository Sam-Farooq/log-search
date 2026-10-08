"""Read the files under `indices/` and compose them the way Elasticsearch does.

A composed index template is not the file you wrote. Elasticsearch merges each
component named in `composed_of`, in that order, then merges the index
template's own `template` block on top. Reading one file tells you almost
nothing about the mapping an index will get, which is the reason this module
exists before anything else in the package.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class TemplateError(Exception):
    """A template file is unusable, or two sources disagree about a field."""


def default_indices_dir() -> Path:
    """Where the template files live.

    `LOGSEARCH_INDICES` wins, so a cluster-specific copy can be linted without
    editing anything. Otherwise `indices/` next to the installed package, which
    is correct for an editable install and for a checkout.
    """
    env = os.environ.get("LOGSEARCH_INDICES")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent / "indices"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TemplateError(f"{path.name}: cannot read: {exc}") from exc
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise TemplateError(f"{path.name}: line {exc.lineno}: {exc.msg}") from exc
    if not isinstance(parsed, dict):
        kind = type(parsed).__name__
        raise TemplateError(f"{path.name}: top level is {kind}, expected an object")
    return parsed


def flatten_settings(settings: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Turn `{"index": {"number_of_shards": 1}}` into `{"index.number_of_shards": 1}`.

    Elasticsearch accepts both shapes and stores the flat one. Two components
    that write the same setting in different shapes look like different
    settings until they are flattened, and then one of them silently wins.
    """
    out: dict[str, Any] = {}
    for key, value in settings.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten_settings(value, f"{path}."))
        else:
            out[path] = value
    return out


@dataclass(frozen=True)
class ComponentTemplate:
    name: str
    path: Path
    settings: dict[str, Any]
    mappings: dict[str, Any]
    meta: dict[str, Any]

    @classmethod
    def load(cls, name: str, path: Path) -> ComponentTemplate:
        doc = _read_json(path)
        template = doc.get("template")
        if not isinstance(template, dict):
            raise TemplateError(f"{path.name}: component template has no `template` object")
        return cls(
            name=name,
            path=path,
            settings=flatten_settings(template.get("settings") or {}),
            mappings=template.get("mappings") or {},
            meta=doc.get("_meta") or {},
        )


@dataclass(frozen=True)
class IndexTemplate:
    name: str
    path: Path
    index_patterns: list[str]
    priority: int
    composed_of: list[str]
    settings: dict[str, Any]
    mappings: dict[str, Any]
    meta: dict[str, Any]

    @property
    def installed(self) -> bool:
        return bool(self.meta.get("installed", True))

    @property
    def write_alias(self) -> str | None:
        alias = self.settings.get("index.lifecycle.rollover_alias")
        return alias if isinstance(alias, str) else None

    @property
    def policy_name(self) -> str | None:
        name = self.settings.get("index.lifecycle.name")
        return name if isinstance(name, str) else None

    @classmethod
    def load(cls, name: str, path: Path) -> IndexTemplate:
        doc = _read_json(path)
        patterns = doc.get("index_patterns")
        if not isinstance(patterns, list) or not patterns:
            raise TemplateError(f"{path.name}: index_patterns is missing or empty")
        template = doc.get("template") or {}
        if not isinstance(template, dict):
            raise TemplateError(f"{path.name}: `template` is not an object")
        return cls(
            name=name,
            path=path,
            index_patterns=[str(p) for p in patterns],
            priority=int(doc.get("priority", 0)),
            composed_of=[str(c) for c in doc.get("composed_of") or []],
            settings=flatten_settings(template.get("settings") or {}),
            mappings=template.get("mappings") or {},
            meta=doc.get("_meta") or {},
        )


@dataclass
class Composed:
    """The mapping and settings an index matching this template would get."""

    name: str
    index_patterns: list[str]
    priority: int
    settings: dict[str, Any]
    mappings: dict[str, Any]
    meta: dict[str, Any]
    sources: dict[str, str] = field(default_factory=dict)
    """Field path to the name of the component or template that defined it."""

    @property
    def dynamic(self) -> str:
        value = self.mappings.get("dynamic", True)
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    @property
    def total_fields_limit(self) -> int:
        return int(self.settings.get("index.mapping.total_fields.limit", 1000))

    @property
    def index_ignore_malformed(self) -> bool:
        return bool(self.settings.get("index.mapping.ignore_malformed", False))

    def properties(self) -> dict[str, Any]:
        props = self.mappings.get("properties") or {}
        return props if isinstance(props, dict) else {}


def _merge_properties(
    into: dict[str, Any],
    new: dict[str, Any],
    source: str,
    sources: dict[str, str],
    prefix: str = "",
) -> None:
    """Merge one source's `properties` into the accumulated mapping.

    Elasticsearch rejects a composition where two sources give one field two
    different types, so this raises rather than picking a winner. Objects merge
    key by key; a leaf is replaced only when the replacement agrees on type.
    """
    for name, definition in new.items():
        path = f"{prefix}{name}"
        if not isinstance(definition, dict):
            raise TemplateError(f"{source}: {path} is not a field definition")
        existing = into.get(name)
        if existing is None:
            into[name] = json.loads(json.dumps(definition))
            sources[path] = source
            _record_nested_sources(definition, source, sources, f"{path}.")
            continue

        old_type = existing.get("type", "object" if "properties" in existing else None)
        new_type = definition.get("type", "object" if "properties" in definition else None)
        if old_type != new_type and old_type is not None and new_type is not None:
            raise TemplateError(
                f"{source}: {path} is {new_type} here and {old_type} in "
                f"{sources.get(path, 'an earlier source')}. Elasticsearch refuses "
                f"this composition at PUT time."
            )

        for key, value in definition.items():
            if key == "properties" and isinstance(value, dict):
                child = existing.setdefault("properties", {})
                _merge_properties(child, value, source, sources, f"{path}.")
            elif key == "fields" and isinstance(value, dict):
                child = existing.setdefault("fields", {})
                _merge_properties(child, value, source, sources, f"{path}.")
            else:
                existing[key] = value


def _record_nested_sources(
    definition: dict[str, Any], source: str, sources: dict[str, str], prefix: str
) -> None:
    for key in ("properties", "fields"):
        child = definition.get(key)
        if isinstance(child, dict):
            for name, sub in child.items():
                sources[f"{prefix}{name}"] = source
                if isinstance(sub, dict):
                    _record_nested_sources(sub, source, sources, f"{prefix}{name}.")


class TemplateSet:
    """Every file under one `indices/` directory, loaded once."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = Path(directory) if directory else default_indices_dir()
        if not self.directory.is_dir():
            raise TemplateError(f"{self.directory} is not a directory")
        self.components: dict[str, ComponentTemplate] = {}
        self.index_templates: dict[str, IndexTemplate] = {}
        self.policies: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        for path in sorted(self.directory.glob("component-*.json")):
            name = path.stem.removeprefix("component-")
            self.components[name] = ComponentTemplate.load(name, path)
        for path in sorted(self.directory.glob("template-*.json")):
            name = path.stem.removeprefix("template-")
            self.index_templates[name] = IndexTemplate.load(name, path)
        for path in sorted(self.directory.glob("ilm-*.json")):
            name = path.stem.removeprefix("ilm-")
            doc = _read_json(path)
            policy = doc.get("policy")
            if not isinstance(policy, dict):
                raise TemplateError(f"{path.name}: no `policy` object")
            self.policies[name] = policy

    @property
    def bootstrap_steps(self) -> list[dict[str, Any]]:
        path = self.directory / "bootstrap-order.json"
        steps = _read_json(path).get("steps")
        if not isinstance(steps, list):
            raise TemplateError("bootstrap-order.json: no `steps` array")
        return [s for s in steps if isinstance(s, dict)]

    def installed_templates(self) -> list[IndexTemplate]:
        return [t for t in self.index_templates.values() if t.installed]

    def compose(self, template_name: str) -> Composed:
        try:
            template = self.index_templates[template_name]
        except KeyError:
            known = ", ".join(sorted(self.index_templates)) or "none"
            raise TemplateError(
                f"no index template named {template_name!r}. Known: {known}"
            ) from None

        settings: dict[str, Any] = {}
        mappings: dict[str, Any] = {}
        sources: dict[str, str] = {}

        for component_name in template.composed_of:
            component = self.components.get(component_name)
            if component is None:
                raise TemplateError(
                    f"{template.path.name}: composed_of names {component_name!r}, "
                    f"which has no component-{component_name}.json. Elasticsearch "
                    f"rejects the template rather than installing it without that part."
                )
            settings.update(component.settings)
            _merge_component_mappings(mappings, component.mappings, component_name, sources)

        settings.update(template.settings)
        _merge_component_mappings(mappings, template.mappings, f"template:{template.name}", sources)

        return Composed(
            name=template.name,
            index_patterns=list(template.index_patterns),
            priority=template.priority,
            settings=settings,
            mappings=mappings,
            meta=dict(template.meta),
            sources=sources,
        )


def _merge_component_mappings(
    into: dict[str, Any], new: dict[str, Any], source: str, sources: dict[str, str]
) -> None:
    for key, value in new.items():
        if key == "properties" and isinstance(value, dict):
            child = into.setdefault("properties", {})
            _merge_properties(child, value, source, sources)
        else:
            into[key] = value
