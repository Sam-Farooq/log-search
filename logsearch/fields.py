"""What a mapping will and will not let you do with each field.

Two questions decide the shape of a log mapping, and they have different
answers for the same data. `keyword` can be filtered on an exact value and
grouped in an aggregation. `text` can be searched for a word inside it and
cannot be grouped at all, because aggregating a text field needs fielddata and
that is off by default. A log message needs both, so it is a multi-field: one
JSON value, two index structures, two names to query.

This module walks a composed mapping and answers the question per field, so the
query builder can refuse an impossible clause instead of emitting one that
returns an empty result with a 200.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from logsearch.templates import Composed

TEXT_TYPES = frozenset({"text", "match_only_text", "annotated_text"})

AGGREGATABLE_TYPES = frozenset(
    {
        "keyword",
        "constant_keyword",
        "wildcard",
        "boolean",
        "ip",
        "date",
        "date_nanos",
        "byte",
        "short",
        "integer",
        "long",
        "unsigned_long",
        "half_float",
        "float",
        "double",
        "scaled_float",
        "flattened",
    }
)

NUMERIC_TYPES = frozenset(
    {
        "byte",
        "short",
        "integer",
        "long",
        "unsigned_long",
        "half_float",
        "float",
        "double",
        "scaled_float",
    }
)

RANGEABLE_TYPES = NUMERIC_TYPES | {"date", "date_nanos", "ip"}

Intent = Literal["term", "match", "match_phrase", "range", "agg", "sort", "exists"]

Kind = Literal["object", "leaf", "multi"]


class FieldUsageError(Exception):
    """A clause was asked for that this mapping cannot answer."""


@dataclass(frozen=True)
class Field:
    path: str
    type: str
    kind: Kind
    source: str
    indexed: bool
    doc_values: bool
    ignore_above: int | None
    ignore_malformed: bool
    phrase_searchable: bool

    @property
    def searchable(self) -> bool:
        return self.kind != "object" and self.indexed

    @property
    def aggregatable(self) -> bool:
        if self.kind == "object":
            return False
        if self.type in TEXT_TYPES:
            return False
        return self.type in AGGREGATABLE_TYPES and self.doc_values

    @property
    def is_text(self) -> bool:
        return self.type in TEXT_TYPES


def _field_type(definition: dict[str, Any]) -> str:
    declared = definition.get("type")
    if isinstance(declared, str):
        return declared
    return "object"


def _walk(
    properties: dict[str, Any],
    prefix: str,
    sources: dict[str, str],
    index_ignore_malformed: bool,
    out: list[Field],
    definitions: dict[str, Any],
) -> None:
    for name, definition in sorted(properties.items()):
        path = f"{prefix}{name}"
        if not isinstance(definition, dict):
            continue
        field_type = _field_type(definition)
        definitions[path] = definition
        children = definition.get("properties")
        multi = definition.get("fields")
        kind: Kind = "object" if field_type == "object" and isinstance(children, dict) else "leaf"
        # `index: false` keeps doc_values, so the field is still aggregatable
        # and sortable while matching nothing. That asymmetry is the whole
        # reason url.query is mapped the way it is.
        indexed = bool(definition.get("index", True)) and kind != "object"
        doc_values = bool(definition.get("doc_values", True)) and kind != "object"
        index_options = definition.get("index_options", "positions")
        phrase = indexed and (
            field_type not in TEXT_TYPES or index_options in {"positions", "offsets"}
        )
        out.append(
            Field(
                path=path,
                type=field_type,
                kind=kind,
                source=sources.get(path, "unknown"),
                indexed=indexed,
                doc_values=doc_values,
                ignore_above=definition.get("ignore_above"),
                ignore_malformed=bool(definition.get("ignore_malformed", index_ignore_malformed)),
                phrase_searchable=phrase,
            )
        )
        if isinstance(children, dict):
            _walk(children, f"{path}.", sources, index_ignore_malformed, out, definitions)
        if isinstance(multi, dict):
            for sub_name, sub in sorted(multi.items()):
                if not isinstance(sub, dict):
                    continue
                sub_type = _field_type(sub)
                definitions[f"{path}.{sub_name}"] = sub
                sub_indexed = bool(sub.get("index", True))
                sub_options = sub.get("index_options", "positions")
                out.append(
                    Field(
                        path=f"{path}.{sub_name}",
                        type=sub_type,
                        kind="multi",
                        source=sources.get(f"{path}.{sub_name}", sources.get(path, "unknown")),
                        indexed=sub_indexed,
                        doc_values=bool(sub.get("doc_values", True)),
                        ignore_above=sub.get("ignore_above"),
                        ignore_malformed=bool(sub.get("ignore_malformed", index_ignore_malformed)),
                        phrase_searchable=sub_indexed
                        and (sub_type not in TEXT_TYPES or sub_options in {"positions", "offsets"}),
                    )
                )


class FieldMap:
    """Every field in one composed mapping, keyed by its full path."""

    def __init__(self, composed: Composed) -> None:
        self.composed = composed
        found: list[Field] = []
        self.definitions: dict[str, Any] = {}
        _walk(
            composed.properties(),
            "",
            composed.sources,
            composed.index_ignore_malformed,
            found,
            self.definitions,
        )
        self.fields: dict[str, Field] = {f.path: f for f in found}

    def __contains__(self, path: object) -> bool:
        return path in self.fields

    def __iter__(self):
        return iter(self.fields.values())

    def __len__(self) -> int:
        return len(self.fields)

    def get(self, path: str) -> Field | None:
        return self.fields.get(path)

    def definition(self, path: str) -> dict[str, Any]:
        """The raw field definition, for the parameters the walk does not carry.

        A date field's `format` list and a flattened field's `depth_limit` only
        matter when a value is being checked against them.
        """
        found = self.definitions.get(path)
        return found if isinstance(found, dict) else {}

    @property
    def total_fields_count(self) -> int:
        """The repo's counting rule: leaf fields, object nodes and multi-fields.

        Metadata fields are excluded. Elasticsearch's own accounting for
        `index.mapping.total_fields.limit` can differ by the root object, so the
        limit in the settings is set with headroom rather than fitted to this
        number. `logsearch lint` prints both.
        """
        return len(self.fields)

    @property
    def headroom(self) -> int:
        return self.composed.total_fields_limit - self.total_fields_count

    def flattened_roots(self) -> list[str]:
        return [f.path for f in self.fields.values() if f.type == "flattened"]

    def within_flattened(self, path: str) -> str | None:
        """Return the flattened root that owns `path`, if any.

        A flattened field has one entry in the mapping and an unbounded set of
        keys underneath it, so `labels.tenant` is never in `self.fields`.
        """
        for root in self.flattened_roots():
            if path.startswith(f"{root}."):
                return root
        return None

    def aggregatable_sibling(self, path: str) -> str | None:
        """The aggregatable half of a multi-field pair, from either side.

        A multi-field can be declared in both directions. `message` is text
        with a `message.raw` keyword under it, and `url.path` is a keyword with
        a `url.path.text` under it. Looking only downwards finds the first and
        reports the second as impossible to aggregate, when the answer was its
        own parent.
        """
        here = self.fields.get(path)
        for candidate in self.fields.values():
            if (
                candidate.kind == "multi"
                and candidate.path.rsplit(".", 1)[0] == path
                and candidate.aggregatable
            ):
                return candidate.path
        if here is not None and here.kind == "multi":
            parent_path = path.rsplit(".", 1)[0]
            parent = self.fields.get(parent_path)
            if parent is not None and parent.aggregatable:
                return parent_path
            for candidate in self.fields.values():
                if (
                    candidate.kind == "multi"
                    and candidate.path != path
                    and candidate.path.rsplit(".", 1)[0] == parent_path
                    and candidate.aggregatable
                ):
                    return candidate.path
        return None

    def resolve(self, path: str, intent: Intent) -> str:
        """The field path to put in the clause, or raise saying why not.

        Every refusal here is a query that Elasticsearch would have accepted
        and answered wrongly or emptily.
        """
        root = self.within_flattened(path)
        if root is not None:
            if intent in {"term", "agg", "sort", "exists", "match"}:
                return path
            raise FieldUsageError(
                f"{path} is a key inside the flattened field {root}, and every value "
                f"under a flattened field is indexed as a keyword. A {intent} clause "
                f"needs a typed field, so promote this key into the mapping first."
            )

        found = self.fields.get(path)
        if found is None:
            close = [p for p in self.fields if p.startswith(path)][:3]
            hint = f" Did you mean {', '.join(close)}?" if close else ""
            raise FieldUsageError(
                f"{path} is not in the {self.composed.name} mapping, and the index is "
                f"dynamic={self.composed.dynamic}. A query naming an unmapped field is "
                f"not an error: it matches nothing and returns 200.{hint}"
            )

        if found.kind == "object":
            raise FieldUsageError(f"{path} is an object, not a field. Name one of its properties.")

        if intent == "exists":
            return path

        if intent == "term":
            if found.is_text:
                sibling = self.aggregatable_sibling(path)
                extra = f" Use {sibling} for an exact match, or match() to search it."
                raise FieldUsageError(
                    f"{path} is {found.type}, so its values were analysed before being "
                    f"indexed. A term query is not analysed, so any term carrying a "
                    f"capital or punctuation matches nothing.{extra if sibling else ''}"
                )
            if not found.indexed:
                raise FieldUsageError(
                    f"{path} is mapped with index: false, so it is in _source and in "
                    f"doc_values but not in the inverted index. It can be aggregated "
                    f"and not filtered."
                )
            return path

        if intent in {"match", "match_phrase"}:
            if not found.indexed:
                raise FieldUsageError(f"{path} is mapped with index: false and matches nothing.")
            if intent == "match_phrase" and not found.phrase_searchable:
                raise FieldUsageError(
                    f"{path} is mapped with index_options: docs, which stores no "
                    f"positions. A phrase query on it returns nothing rather than "
                    f"failing. Use match() instead."
                )
            return path

        if intent == "range":
            if found.type not in RANGEABLE_TYPES:
                raise FieldUsageError(
                    f"{path} is {found.type}. A range query on it compares strings "
                    f"byte by byte, so gte: 'warn' excludes 'error' and nothing reports "
                    f"a problem. Use a terms clause over an explicit list instead."
                )
            return path

        if intent in {"agg", "sort"}:
            if found.aggregatable:
                return path
            sibling = self.aggregatable_sibling(path)
            if sibling is not None:
                return sibling
            if found.is_text:
                raise FieldUsageError(
                    f"{path} is {found.type} with no keyword multi-field, so it cannot "
                    f"be aggregated without turning fielddata on, which loads every "
                    f"term in the field into the heap."
                )
            raise FieldUsageError(
                f"{path} is mapped with doc_values: false and cannot be {intent}ed."
            )

        raise FieldUsageError(f"unknown intent {intent!r} for {path}")
