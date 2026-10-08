"""Build search bodies that only name fields the mapping defines.

An Elasticsearch query is wrong in one of two ways. It fails, which is fine,
because something tells you. Or it succeeds and answers a different question:
a term query against an analysed field, a range over a keyword, an aggregation
on a field nobody mapped. All three return 200 with an empty or misleading
result, and nothing in the response says a word.

So every clause here goes through FieldMap.resolve first, and the builder
refuses to emit one the mapping cannot answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any

from logsearch.fields import FieldMap, FieldUsageError

LEVELS: tuple[str, ...] = ("trace", "debug", "info", "warn", "error", "fatal")
"""Ordered by severity, which is the order a keyword field does not know about.

`log.level` is a keyword. A range query on it compares bytes, and in that order
`error` sorts below `info`, so `{"range": {"log.level": {"gte": "warn"}}}`
returns warnings and drops every error and fatal in the index. It is a
successful query with a wrong answer, which is why level_at_least() emits a
terms clause over this tuple instead.
"""

METADATA_FIELDS = frozenset({"_ignored", "_index", "_id"})
"""Queryable without being in the mapping.

`_ignored` is the only record that a field was dropped by ignore_malformed. It
names the field and never the value.
"""

DEFAULT_SOURCE = (
    "@timestamp",
    "message",
    "log.level",
    "service.name",
    "event.id",
    "trace.id",
)


class QueryError(Exception):
    """The query asked for cannot be built."""


@dataclass
class LogQuery:
    """A search body, assembled clause by clause."""

    field_map: FieldMap
    size: int = 50
    time_field: str = "@timestamp"
    tiebreaker: str = "event.id"
    _filters: list[dict[str, Any]] = dataclass_field(default_factory=list)
    _musts: list[dict[str, Any]] = dataclass_field(default_factory=list)
    _must_nots: list[dict[str, Any]] = dataclass_field(default_factory=list)
    _aggs: dict[str, Any] = dataclass_field(default_factory=dict)
    _sort: list[dict[str, Any]] = dataclass_field(default_factory=list)
    _after: list[Any] | None = None
    _total_hits: int | bool = 10_000
    _source: tuple[str, ...] | None = None
    _notes: list[str] = dataclass_field(default_factory=list)

    # ----- time -------------------------------------------------------------

    def window(self, gte: str, lte: str = "now", time_zone: str | None = None) -> LogQuery:
        """A range on the time field, in filter context.

        The range is on a date field, so it is the one range clause here that
        is not a mistake.
        """
        self.field_map.resolve(self.time_field, "range")
        clause: dict[str, Any] = {
            "gte": gte,
            "lte": lte,
            "format": "strict_date_optional_time||epoch_millis",
        }
        if time_zone:
            # The offset applies to the bounds, not to what is stored. A date is
            # UTC in the index whatever the query says.
            clause["time_zone"] = time_zone
        self._filters.append({"range": {self.time_field: clause}})
        return self

    # ----- filters ----------------------------------------------------------

    def terms(self, path: str, values: list[Any]) -> LogQuery:
        if not values:
            raise QueryError(f"terms on {path} with no values matches nothing. Leave it out.")
        resolved = self.field_map.resolve(path, "term")
        self._filters.append({"terms": {resolved: list(values)}})
        return self

    def term(self, path: str, value: Any) -> LogQuery:
        resolved = self.field_map.resolve(path, "term")
        self._filters.append({"term": {resolved: value}})
        return self

    def service(self, *names: str) -> LogQuery:
        return self.terms("service.name", list(names))

    def level_at_least(self, level: str) -> LogQuery:
        """Everything at or above a severity, as a terms clause.

        See the note on LEVELS for what the obvious version does instead.
        """
        level = level.lower()
        if level not in LEVELS:
            raise QueryError(f"{level!r} is not one of {', '.join(LEVELS)}")
        wanted = list(LEVELS[LEVELS.index(level) :])
        self._notes.append(
            f"level >= {level} is a terms clause over {len(wanted)} values, not a range, "
            f"because log.level is a keyword and a range on it sorts error below info"
        )
        return self.terms("log.level", wanted)

    def label(self, key: str, value: Any) -> LogQuery:
        """A term on one key inside the flattened catch-all.

        A mapping with no catch-all, which is how logs-audit is written, has no
        key to put this on, and resolve says so rather than inventing one.
        """
        roots = self.field_map.flattened_roots()
        root = roots[0] if roots else "labels"
        return self.term(f"{root}.{key}", value)

    def status_between(self, gte: int | None = None, lte: int | None = None) -> LogQuery:
        return self.range("http.response.status_code", gte=gte, lte=lte)

    def range(self, path: str, gte: Any = None, lte: Any = None) -> LogQuery:
        if gte is None and lte is None:
            raise QueryError(f"a range on {path} needs at least one bound")
        resolved = self.field_map.resolve(path, "range")
        bounds = {k: v for k, v in (("gte", gte), ("lte", lte)) if v is not None}
        self._filters.append({"range": {resolved: bounds}})
        return self

    def exists(self, path: str) -> LogQuery:
        resolved = path if path in METADATA_FIELDS else self.field_map.resolve(path, "exists")
        self._filters.append({"exists": {"field": resolved}})
        return self

    def without(self, path: str, value: Any) -> LogQuery:
        resolved = path if path in METADATA_FIELDS else self.field_map.resolve(path, "term")
        self._must_nots.append({"term": {resolved: value}})
        return self

    def with_dropped_fields(self, path: str | None = None) -> LogQuery:
        """Documents where ignore_malformed threw a field away.

        This is the only query that finds them. It returns the field name and
        never the value, which stays in _source and in no index.
        """
        if path is None:
            self._filters.append({"exists": {"field": "_ignored"}})
        else:
            self._filters.append({"term": {"_ignored": path}})
        self._notes.append("_ignored names the dropped field, never the value it held")
        return self

    # ----- scored clauses ---------------------------------------------------

    def message(self, text: str, field: str = "message") -> LogQuery:
        """The one clause that scores. Everything else is a filter."""
        resolved = self.field_map.resolve(field, "match")
        self._musts.append({"match": {resolved: {"query": text}}})
        return self

    def phrase(self, text: str, field: str = "message") -> LogQuery:
        resolved = self.field_map.resolve(field, "match_phrase")
        self._musts.append({"match_phrase": {resolved: text}})
        return self

    # ----- aggregations -----------------------------------------------------

    def count_by(self, path: str, size: int = 10, name: str | None = None) -> LogQuery:
        """A terms aggregation, with shard_size written down.

        Elasticsearch picks size * 1.5 + 10 when shard_size is left out. Each
        shard returns its own top N and the coordinating node adds them up, so
        a term that is eleventh on every shard and first overall can be missed.
        doc_count_error_upper_bound in the response is how far out the counts
        could be, and sum_other_doc_count is what fell off the end.
        """
        resolved = self.field_map.resolve(path, "agg")
        key = name or f"by_{path.replace('.', '_')}"
        self._aggs[key] = {
            "terms": {
                "field": resolved,
                "size": size,
                "shard_size": int(size * 1.5) + 10,
                "order": {"_count": "desc"},
            }
        }
        return self

    def over_time(self, interval: str = "5m", name: str = "over_time") -> LogQuery:
        """A date histogram that keeps its empty buckets.

        min_doc_count 0 costs a bucket per empty interval and is worth it: a
        gap in a log volume chart is either a quiet system or a shipper that
        stopped, and a chart that skips the gap cannot tell you which.
        """
        self.field_map.resolve(self.time_field, "agg")
        self._aggs[name] = {
            "date_histogram": {
                "field": self.time_field,
                "fixed_interval": interval,
                "min_doc_count": 0,
            }
        }
        return self

    def percentiles(self, path: str, percents: tuple[float, ...] = (50, 95, 99)) -> LogQuery:
        resolved = self.field_map.resolve(path, "agg")
        field = self.field_map.get(resolved)
        if field is None or field.type not in {
            "byte",
            "short",
            "integer",
            "long",
            "unsigned_long",
            "half_float",
            "float",
            "double",
            "scaled_float",
        }:
            raise QueryError(f"percentiles need a numeric field and {path} is not one")
        self._aggs[f"{path.replace('.', '_')}_percentiles"] = {
            "percentiles": {"field": resolved, "percents": list(percents)}
        }
        return self

    def distinct(self, path: str, name: str | None = None) -> LogQuery:
        """A cardinality aggregation, which is an estimate and says so."""
        resolved = self.field_map.resolve(path, "agg")
        self._aggs[name or f"distinct_{path.replace('.', '_')}"] = {
            "cardinality": {"field": resolved}
        }
        self._notes.append(f"cardinality on {resolved} is a HyperLogLog++ estimate, not a count")
        return self

    # ----- paging and output ------------------------------------------------

    def page(self, size: int) -> LogQuery:
        if size < 0:
            raise QueryError("size cannot be negative")
        limit = int(self.field_map.composed.settings.get("index.max_result_window", 10_000))
        if size > limit:
            raise QueryError(
                f"size {size} is past index.max_result_window ({limit}). Page with "
                f"after() instead of asking for one enormous page."
            )
        self.size = size
        return self

    def after(self, sort_values: list[Any]) -> LogQuery:
        """search_after, which is how you page past max_result_window.

        from + size makes every shard build and sort from the first hit again,
        so page 500 costs 500 pages of work on each shard and the cluster
        refuses past max_result_window. search_after resumes from the previous
        page's sort values, which costs nothing extra, and needs a sort that is
        unique per document, hence the tiebreaker.

        Without a point in time, documents indexed between pages shift the
        sort, so a row can be seen twice or missed. This builder takes the
        tiebreaker rather than a PIT, because a PIT holds segments open on
        every shard for as long as it lives and this is a log search, not a
        report that has to be exactly consistent.
        """
        self._after = list(sort_values)
        return self

    def sort_by(self, path: str, order: str = "desc") -> LogQuery:
        resolved = self.field_map.resolve(path, "sort")
        self._sort.append({resolved: {"order": order}})
        return self

    def total_hits(self, value: int | bool) -> LogQuery:
        """How far to count.

        The default stops at 10,000 and reports `gte`, because counting every
        match means visiting every match. `True` is a real cost on a large
        index and the only way to get an exact number.
        """
        self._total_hits = value
        return self

    def source(self, *paths: str) -> LogQuery:
        for path in paths:
            if path not in self.field_map and self.field_map.within_flattened(path) is None:
                raise FieldUsageError(
                    f"{path} is not in the {self.field_map.composed.name} mapping"
                )
        self._source = tuple(paths)
        return self

    # ----- output -----------------------------------------------------------

    def body(self) -> dict[str, Any]:
        sort = list(self._sort) or [{self.time_field: {"order": "desc"}}]
        if self.tiebreaker and not any(self.tiebreaker in clause for clause in sort):
            sort.append({self.tiebreaker: {"order": "asc"}})

        boolean: dict[str, Any] = {}
        if self._filters:
            boolean["filter"] = self._filters
        if self._musts:
            boolean["must"] = self._musts
        if self._must_nots:
            boolean["must_not"] = self._must_nots

        body: dict[str, Any] = {
            "size": self.size,
            "track_total_hits": self._total_hits,
            # A bool with only filter clauses scores nothing and is cacheable in
            # the node query cache. Putting these in `must` would score every
            # hit by a relevance nobody reads.
            "query": {"bool": boolean} if boolean else {"match_all": {}},
            "sort": sort,
        }
        if self._source is not None:
            body["_source"] = {"includes": list(self._source)}
        if self._aggs:
            body["aggs"] = self._aggs
        if self._after is not None:
            if len(self._after) != len(sort):
                raise QueryError(
                    f"search_after needs one value per sort key: {len(sort)} sort keys, "
                    f"{len(self._after)} values"
                )
            body["search_after"] = self._after
        return body

    def notes(self) -> list[str]:
        return list(self._notes)
