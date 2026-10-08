"""Read an ILM policy and work out what it implies.

A retention policy is two numbers and an arithmetic nobody does: how often the
index rolls, and how long a rolled index is kept. Those two give the number of
live indices, and the rollover size gives the ceiling. Every number this module
prints comes from the policy file, and none of it has been observed.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

PHASE_ORDER: tuple[str, ...] = ("hot", "warm", "cold", "frozen", "delete")

_DURATION = re.compile(r"^(\d+(?:\.\d+)?)(d|h|m|s|ms|micros|nanos)$")

_IN_DAYS = {
    "d": 1.0,
    "h": 1 / 24,
    "m": 1 / 1440,
    "s": 1 / 86_400,
    "ms": 1 / 86_400_000,
    "micros": 1 / 86_400_000_000,
    "nanos": 1 / 86_400_000_000_000,
}

_SIZE = re.compile(r"^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb|tb|pb)$", re.IGNORECASE)

_IN_GB = {
    "b": 1 / 1024**3,
    "kb": 1 / 1024**2,
    "mb": 1 / 1024,
    "gb": 1.0,
    "tb": 1024.0,
    "pb": 1024.0**2,
}


class LifecycleError(Exception):
    """The policy cannot be read, or says something impossible."""


def duration_in_days(text: str) -> float:
    match = _DURATION.match(text.strip())
    if match is None:
        raise LifecycleError(f"{text!r} is not an Elasticsearch time value")
    return float(match.group(1)) * _IN_DAYS[match.group(2)]


def size_in_gb(text: str) -> float:
    match = _SIZE.match(text.strip())
    if match is None:
        raise LifecycleError(f"{text!r} is not an Elasticsearch byte value")
    return float(match.group(1)) * _IN_GB[match.group(2).lower()]


@dataclass(frozen=True)
class Phase:
    name: str
    min_age_days: float
    actions: dict[str, Any]

    @property
    def action_names(self) -> list[str]:
        return sorted(self.actions)


@dataclass(frozen=True)
class Ceiling:
    live_indices: int
    per_index_gb: float
    primary_gb: float
    on_disk_gb: float

    def __str__(self) -> str:
        return (
            f"{self.live_indices} live indices at {self.per_index_gb:g}gb per primary is "
            f"{self.primary_gb:g}gb of primaries and {self.on_disk_gb:g}gb on disk"
        )


@dataclass
class Policy:
    name: str
    phases: list[Phase]
    meta: dict[str, Any]

    @classmethod
    def load(cls, name: str, policy: dict[str, Any]) -> Policy:
        raw = policy.get("phases")
        if not isinstance(raw, dict) or not raw:
            raise LifecycleError(f"{name}: the policy has no phases")
        unknown = sorted(set(raw) - set(PHASE_ORDER))
        if unknown:
            raise LifecycleError(f"{name}: {', '.join(unknown)} is not an ILM phase")
        phases = [
            Phase(
                name=phase_name,
                min_age_days=duration_in_days(str(raw[phase_name].get("min_age", "0d"))),
                actions=raw[phase_name].get("actions") or {},
            )
            for phase_name in PHASE_ORDER
            if phase_name in raw
        ]
        return cls(name=name, phases=phases, meta=policy.get("_meta") or {})

    def phase(self, name: str) -> Phase | None:
        for phase in self.phases:
            if phase.name == name:
                return phase
        return None

    @property
    def write_alias(self) -> str | None:
        alias = self.meta.get("write_alias")
        return alias if isinstance(alias, str) else None

    @property
    def rollover(self) -> dict[str, Any]:
        hot = self.phase("hot")
        rollover = hot.actions.get("rollover") if hot else None
        return rollover if isinstance(rollover, dict) else {}

    @property
    def rollover_age_days(self) -> float | None:
        value = self.rollover.get("max_age")
        return duration_in_days(str(value)) if value else None

    @property
    def rollover_size_gb(self) -> float | None:
        for key in ("max_primary_shard_size", "max_size"):
            if key in self.rollover:
                return size_in_gb(str(self.rollover[key]))
        return None

    @property
    def delete_after_days(self) -> float | None:
        delete = self.phase("delete")
        return delete.min_age_days if delete else None

    def ceiling(self, primaries: int = 1, replicas: int = 1) -> Ceiling:
        """How large this policy lets the index set get.

        One more index than the division, because the write index has not
        rolled yet. `max_primary_shard_size` is per primary, so the per index
        figure multiplies by the shard count, and replicas multiply the disk.
        """
        age = self.rollover_age_days
        kept = self.delete_after_days
        size = self.rollover_size_gb
        if age is None or kept is None or size is None:
            raise LifecycleError(
                f"{self.name}: a ceiling needs a rollover max_age, a rollover size and a "
                f"delete phase. Missing: "
                + ", ".join(
                    label
                    for label, value in (
                        ("max_age", age),
                        ("rollover size", size),
                        ("delete min_age", kept),
                    )
                    if value is None
                )
            )
        live = math.ceil(kept / age) + 1
        per_index = size * primaries
        primary_total = live * per_index
        return Ceiling(
            live_indices=live,
            per_index_gb=per_index,
            primary_gb=primary_total,
            on_disk_gb=primary_total * (1 + replicas),
        )

    def out_of_order_phases(self) -> list[str]:
        """Phases whose min_age is not greater than the phase before it.

        ILM moves an index through the phases in order and a later phase with
        an earlier min_age never gets its own window: the index arrives already
        past it. Nothing errors, and the phase in the middle looks like it ran.
        """
        problems: list[str] = []
        previous: Phase | None = None
        for phase in self.phases:
            if previous is not None and phase.min_age_days < previous.min_age_days:
                problems.append(
                    f"{phase.name} min_age {phase.min_age_days:g}d is earlier than "
                    f"{previous.name} min_age {previous.min_age_days:g}d"
                )
            previous = phase
        return problems

    def timeline(self) -> list[str]:
        lines = []
        for phase in self.phases:
            when = (
                "on rollover"
                if phase.min_age_days == 0
                else f"{phase.min_age_days:g}d after rollover"
            )
            lines.append(f"{phase.name:<7} {when:<22} {', '.join(phase.action_names) or 'nothing'}")
        return lines
