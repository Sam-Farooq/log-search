"""What Elasticsearch does with a value its mapping cannot hold.

This is a model of the parse rules, not a cluster. It exists because the
interesting cases are the ones you cannot see: a field that arrives as a string
from one service and a number from another is a mapping conflict, and the three
usual answers to it fail in three different ways.

    strict            the document is rejected. The bulk response carries the
                      item error, the line is gone, and you know.
    ignore_malformed  the field is not indexed. The document is indexed, the
                      response is a 201, `_source` still shows the value, and
                      the field is invisible to every query and aggregation.
                      `_ignored` is the only place that records it.
    normalize         the producer side converts what it can and diverts what
                      it cannot, so the cluster only ever sees values its
                      mapping holds.

The verdicts here are meant to be checked against a real cluster by the tests
marked `live`, which the CI workflow points at a service container. That
workflow has not run, so the check is configuration rather than a result. Where
this model and Elasticsearch disagree, this model is wrong, and that test is how
it would be found.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from logsearch.fields import NUMERIC_TYPES, TEXT_TYPES, Field

INTEGER_TYPES = frozenset({"byte", "short", "integer", "long", "unsigned_long"})

INTEGER_BOUNDS: dict[str, tuple[int, int]] = {
    "byte": (-128, 127),
    "short": (-32768, 32767),
    "integer": (-(2**31), 2**31 - 1),
    "long": (-(2**63), 2**63 - 1),
    "unsigned_long": (0, 2**64 - 1),
}

KNOWN_DATE_FORMATS = frozenset(
    {"strict_date_optional_time", "epoch_millis", "epoch_second", "date_optional_time"}
)

_DURATION = re.compile(r"^(\d+(?:\.\d+)?)\s*(ms|s|m|h)$")

_DURATION_IN_MS = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000}


class Verdict(StrEnum):
    OK = "ok"
    COERCED = "coerced"
    """Elasticsearch accepts it and changes it: "200" into a long, 200 into a keyword."""
    MALFORMED = "malformed"
    """The parser for this field's type refuses the value."""
    SHAPE = "shape"
    """Elasticsearch raises document_parsing_exception and ignore_malformed does
    not cover it, so the whole document is rejected whatever the strategy.

    Two cases reach this. An object given to a field mapped as a scalar, and a
    flattened field nested deeper than its depth_limit. The second one was
    classified MALFORMED until a real cluster disagreed: the lenient mapping
    rejected e-0042 with document_parsing_exception on labels, where this model
    had predicted ignore_malformed would absorb it and index the document with
    the field unindexed."""
    OVER_IGNORE_ABOVE = "over_ignore_above"
    """A keyword longer than ignore_above. Stored in _source, absent from the index."""
    UNMAPPED = "unmapped"


@dataclass(frozen=True)
class Check:
    verdict: Verdict
    reason: str = ""
    normalized: Any = None
    """A value this field could hold, when one can be derived. None otherwise."""

    @property
    def indexed(self) -> bool:
        return self.verdict in {Verdict.OK, Verdict.COERCED}


def unknown_date_formats(declared: str | None) -> list[str]:
    """Formats this checker cannot judge a value against.

    The lint fails on a non-empty result rather than guessing, because a date
    format nobody modelled turns every verdict about that field into a shrug.
    """
    return [fmt for fmt in date_formats_from(declared) if fmt not in KNOWN_DATE_FORMATS]


def date_formats_from(declared: str | None) -> list[str]:
    raw = declared or "strict_date_optional_time||epoch_millis"
    return [part.strip() for part in raw.split("||") if part.strip()]


def _duration_to_ms(text: str) -> float | None:
    match = _DURATION.match(text.strip())
    if match is None:
        return None
    return float(match.group(1)) * _DURATION_IN_MS[match.group(2)]


def _check_integer(value: Any, field_type: str, path: str) -> Check:
    low, high = INTEGER_BOUNDS.get(field_type, INTEGER_BOUNDS["long"])
    if isinstance(value, bool):
        return Check(
            Verdict.MALFORMED, f"{path}: a boolean is not a number to the {field_type} parser"
        )
    if isinstance(value, int):
        if low <= value <= high:
            return Check(Verdict.OK, normalized=value)
        return Check(
            Verdict.MALFORMED,
            f"{path}: {value} is outside the range of {field_type} ({low} to {high})",
            normalized=None,
        )
    if isinstance(value, float):
        if value.is_integer() and low <= value <= high:
            return Check(
                Verdict.COERCED, f"{path}: {value} truncated to fit {field_type}", int(value)
            )
        return Check(
            Verdict.MALFORMED, f"{path}: {value} has a fractional part and {field_type} does not"
        )
    if isinstance(value, str):
        text = value.strip()
        try:
            number = float(text)
        except ValueError:
            as_ms = _duration_to_ms(text) if path.endswith("_ms") else None
            if as_ms is not None and as_ms.is_integer():
                return Check(
                    Verdict.MALFORMED,
                    f"{path}: {value!r} is a duration with a unit, not a number",
                    int(as_ms),
                )
            return Check(Verdict.MALFORMED, f"{path}: {value!r} does not parse as {field_type}")
        if not number.is_integer():
            return Check(
                Verdict.MALFORMED, f"{path}: {value!r} is fractional and {field_type} is not"
            )
        if not low <= number <= high:
            return Check(
                Verdict.MALFORMED, f"{path}: {value!r} is outside the range of {field_type}"
            )
        return Check(
            Verdict.COERCED, f"{path}: the string {value!r} is parsed as a number", int(number)
        )
    return Check(Verdict.MALFORMED, f"{path}: {type(value).__name__} is not a {field_type}")


def _check_float(value: Any, field_type: str, path: str) -> Check:
    if isinstance(value, bool):
        return Check(Verdict.MALFORMED, f"{path}: a boolean is not a {field_type}")
    if isinstance(value, (int, float)):
        return Check(Verdict.OK, normalized=float(value))
    if isinstance(value, str):
        try:
            return Check(
                Verdict.COERCED,
                f"{path}: the string {value!r} is parsed as a number",
                float(value.strip()),
            )
        except ValueError:
            as_ms = _duration_to_ms(value) if path.endswith("_ms") else None
            if as_ms is not None:
                return Check(
                    Verdict.MALFORMED,
                    f"{path}: {value!r} is a duration with a unit, not a number",
                    as_ms,
                )
            return Check(Verdict.MALFORMED, f"{path}: {value!r} does not parse as {field_type}")
    return Check(Verdict.MALFORMED, f"{path}: {type(value).__name__} is not a {field_type}")


def _check_date(value: Any, path: str, formats: list[str]) -> Check:
    epoch_allowed = {"epoch_millis", "epoch_second"} & set(formats)
    iso_allowed = {"strict_date_optional_time", "date_optional_time"} & set(formats)
    if isinstance(value, bool):
        return Check(Verdict.MALFORMED, f"{path}: a boolean is not a date")
    if isinstance(value, (int, float)):
        if epoch_allowed:
            return Check(Verdict.OK, normalized=int(value))
        return Check(
            Verdict.MALFORMED,
            f"{path}: {value} is a number and the format list is {'||'.join(formats)}, "
            f"which has no epoch form",
        )
    if isinstance(value, str):
        text = value.strip()
        if iso_allowed:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                pass
            else:
                return Check(Verdict.OK, normalized=parsed.isoformat())
        if epoch_allowed and re.fullmatch(r"-?\d+", text):
            return Check(
                Verdict.COERCED, f"{path}: the string {text!r} is read as an epoch", int(text)
            )
        return Check(
            Verdict.MALFORMED,
            f"{path}: {value!r} does not match {'||'.join(formats)}",
        )
    return Check(Verdict.MALFORMED, f"{path}: {type(value).__name__} is not a date")


def _check_ip(value: Any, path: str) -> Check:
    if isinstance(value, str):
        try:
            ipaddress.ip_address(value.strip())
        except ValueError:
            return Check(Verdict.MALFORMED, f"{path}: {value!r} is not an IP address")
        return Check(Verdict.OK, normalized=value.strip())
    return Check(
        Verdict.MALFORMED, f"{path}: an IP field needs a string, not {type(value).__name__}"
    )


def _check_boolean(value: Any, path: str) -> Check:
    if isinstance(value, bool):
        return Check(Verdict.OK, normalized=value)
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return Check(
            Verdict.COERCED,
            f"{path}: the string {value!r} is read as a boolean",
            value.strip().lower() == "true",
        )
    return Check(Verdict.MALFORMED, f"{path}: {value!r} is not a boolean")


def _check_keyword(value: Any, field: Field, path: str) -> Check:
    limit = field.ignore_above
    if isinstance(value, str):
        if limit is not None and len(value) > limit:
            return Check(
                Verdict.OVER_IGNORE_ABOVE,
                f"{path}: {len(value)} characters against ignore_above {limit}. The value "
                f"stays in _source and is not in the index, so it is readable in a hit "
                f"and absent from every term query and aggregation",
                normalized=value,
            )
        return Check(Verdict.OK, normalized=value)
    if isinstance(value, bool):
        return Check(
            Verdict.COERCED,
            f"{path}: the boolean {value} is stored as its string form",
            str(value).lower(),
        )
    if isinstance(value, (int, float)):
        return Check(
            Verdict.COERCED, f"{path}: the number {value} is stored as its string form", str(value)
        )
    return Check(Verdict.MALFORMED, f"{path}: {type(value).__name__} is not a keyword value")


def _check_text(value: Any, path: str) -> Check:
    if isinstance(value, str):
        return Check(Verdict.OK, normalized=value)
    if isinstance(value, bool):
        return Check(
            Verdict.COERCED, f"{path}: the boolean {value} is analysed as text", str(value).lower()
        )
    if isinstance(value, (int, float)):
        return Check(Verdict.COERCED, f"{path}: the number {value} is analysed as text", str(value))
    return Check(Verdict.MALFORMED, f"{path}: {type(value).__name__} is not text")


def _check_flattened(value: Any, field: Field, path: str, limit: int, depth: int = 1) -> Check:
    if isinstance(value, dict):
        if depth > limit:
            # SHAPE, not MALFORMED: ignore_malformed does not rescue a flattened
            # field that is too deep. Elasticsearch raises
            # document_parsing_exception and drops the document under every
            # strategy, which is what the first live run showed.
            return Check(Verdict.SHAPE, f"{path}: nested deeper than depth_limit {limit}")
        for key, sub in value.items():
            check = _check_flattened(sub, field, f"{path}.{key}", limit, depth + 1)
            if check.verdict is not Verdict.OK:
                return check
        return Check(Verdict.OK, normalized=value)
    if isinstance(value, list):
        for item in value:
            check = _check_flattened(item, field, path, limit, depth)
            if check.verdict is not Verdict.OK:
                return check
        return Check(Verdict.OK, normalized=value)
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, str) and field.ignore_above and len(value) > field.ignore_above:
            return Check(
                Verdict.OVER_IGNORE_ABOVE,
                f"{path}: {len(value)} characters against the flattened ignore_above "
                f"{field.ignore_above}, so this key is in _source and not in the index",
                normalized=value,
            )
        return Check(Verdict.OK, normalized=value)
    return Check(
        Verdict.MALFORMED, f"{path}: {type(value).__name__} cannot go in a flattened field"
    )


def check_value(value: Any, field: Field, declared: dict[str, Any] | None = None) -> Check:
    """Classify one value against one mapped field.

    `declared` is the raw field definition, used only for a date field's format
    list, which is not on the walked Field.
    """
    path = field.path
    if value is None:
        return Check(Verdict.OK, f"{path}: null is skipped rather than indexed", None)

    if isinstance(value, list):
        worst = Check(Verdict.OK, normalized=[])
        values: list[Any] = []
        for item in value:
            check = check_value(item, field, declared)
            values.append(check.normalized)
            if _severity(check.verdict) > _severity(worst.verdict):
                worst = check
        return Check(worst.verdict, worst.reason, values if worst.indexed else worst.normalized)

    field_type = field.type

    if field_type == "flattened":
        depth_limit = int((declared or {}).get("depth_limit", 20))
        return _check_flattened(value, field, path, depth_limit)

    if isinstance(value, dict):
        return Check(
            Verdict.SHAPE,
            f"{path}: an object was sent to a field mapped as {field_type}. "
            f"ignore_malformed does not cover this case, so the whole document is "
            f"rejected whatever that setting says",
        )

    if field_type in INTEGER_TYPES:
        return _check_integer(value, field_type, path)
    if field_type in NUMERIC_TYPES:
        return _check_float(value, field_type, path)
    if field_type in {"date", "date_nanos"}:
        formats = date_formats_from((declared or {}).get("format"))
        return _check_date(value, path, formats)
    if field_type == "ip":
        return _check_ip(value, path)
    if field_type == "boolean":
        return _check_boolean(value, path)
    if field_type in TEXT_TYPES:
        return _check_text(value, path)
    if field_type in {"keyword", "constant_keyword", "wildcard"}:
        return _check_keyword(value, field, path)
    return Check(
        Verdict.OK, f"{path}: {field_type} is not modelled here, so it is left alone", value
    )


_SEVERITY = {
    Verdict.OK: 0,
    Verdict.COERCED: 1,
    Verdict.OVER_IGNORE_ABOVE: 2,
    Verdict.UNMAPPED: 3,
    Verdict.MALFORMED: 4,
    Verdict.SHAPE: 5,
}


def _severity(verdict: Verdict) -> int:
    return _SEVERITY[verdict]
