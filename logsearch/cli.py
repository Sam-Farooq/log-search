"""The command line. Everything here runs against the files, not a cluster.

Exit codes, because this is only useful if a build can act on it:

    0  nothing to report
    1  the linter found an error, or the ingest report lost something
    2  refused: usage, an unreadable file, an unknown template or field
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from logsearch import __version__
from logsearch.fields import FieldMap, FieldUsageError
from logsearch.ingest import Strategy, StrategyMismatch, bulk_operations, run
from logsearch.lifecycle import LifecycleError, Policy
from logsearch.lint import Level, lint
from logsearch.query import LogQuery, QueryError
from logsearch.templates import TemplateError, TemplateSet

OK = 0
FINDINGS = 1
REFUSED = 2

STRATEGY_MAPPING = {
    Strategy.STRICT: "logs-app",
    Strategy.IGNORE_MALFORMED: "logs-app-lenient",
    Strategy.NORMALIZE: "logs-app",
}


def _load(args: argparse.Namespace) -> TemplateSet:
    return TemplateSet(Path(args.indices) if args.indices else None)


def _field_map(templates: TemplateSet, name: str) -> FieldMap:
    return FieldMap(templates.compose(name))


def _read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise TemplateError(f"{path.name}: line {number}: {exc.msg}") from exc
    return events


# ----- commands -------------------------------------------------------------


def cmd_lint(args: argparse.Namespace) -> int:
    templates = _load(args)
    findings = lint(templates)
    for finding in findings:
        print(finding)
    failures = [f for f in findings if f.level is Level.ERROR]
    print(
        f"\n{len(templates.index_templates)} index templates, "
        f"{len(templates.components)} components, {len(templates.policies)} policies: "
        f"{len(failures)} errors, {len(findings) - len(failures)} notes"
    )
    return FINDINGS if failures else OK


def cmd_fields(args: argparse.Namespace) -> int:
    templates = _load(args)
    field_map = _field_map(templates, args.mapping)
    print(f"{'field':<34} {'type':<14} {'search':<7} {'agg':<5} source")
    shown = 0
    for field in field_map:
        if args.grep and args.grep not in field.path:
            continue
        shown += 1
        print(
            f"{field.path:<34} {field.type:<14} "
            f"{'yes' if field.searchable else 'no':<7} "
            f"{'yes' if field.aggregatable else 'no':<5} {field.source}"
        )
    print(
        f"\n{shown} shown of {field_map.total_fields_count} counted against a limit of "
        f"{field_map.composed.total_fields_limit}, dynamic={field_map.composed.dynamic}"
    )
    return OK


def cmd_explain(args: argparse.Namespace) -> int:
    templates = _load(args)
    field_map = _field_map(templates, args.mapping)
    path = args.field
    root = field_map.within_flattened(path)
    if root:
        print(f"{path} is a key inside the flattened field {root}")
        print("  every value under it is indexed as a keyword, whatever type it arrived as")
    field = field_map.get(path)
    if field is None and root is None:
        print(f"{path} is not in the {args.mapping} mapping")
        print(f"  dynamic is {field_map.composed.dynamic}")
        print("  a query naming it returns 200 and matches nothing")
    elif field is not None:
        definition = field_map.definition(path)
        print(f"{path}")
        print(f"  type          {field.type} ({field.kind}), from {field.source}")
        print(f"  searchable    {'yes' if field.searchable else 'no'}")
        print(f"  aggregatable  {'yes' if field.aggregatable else 'no'}")
        if field.ignore_above is not None:
            print(f"  ignore_above  {field.ignore_above} characters, then dropped from the index")
        if not field.phrase_searchable:
            print("  phrases       no, index_options stores no positions")
        multi = field_map.multi_fields_of(path)
        if multi:
            print(f"  multi-fields  {', '.join(f'{p} ({f.type})' for p, f in multi)}")
        if definition.get("format"):
            print(f"  format        {definition['format']}")
    for intent in ("term", "match", "match_phrase", "range", "agg", "sort"):
        try:
            resolved = field_map.resolve(path, intent)  # type: ignore[arg-type]
        except FieldUsageError as exc:
            print(f"  {intent:<13} refused: {exc}")
        else:
            arrow = "" if resolved == path else f" -> {resolved}"
            print(f"  {intent:<13} ok{arrow}")
    return OK


def cmd_query(args: argparse.Namespace) -> int:
    templates = _load(args)
    query = LogQuery(_field_map(templates, args.mapping))
    if args.since:
        query.window(args.since, args.until)
    if args.service:
        query.service(*args.service)
    if args.level:
        query.level_at_least(args.level)
    if args.message:
        query.message(args.message)
    for pair in args.label or []:
        key, _, value = pair.partition("=")
        if not value:
            raise QueryError(f"--label wants key=value, got {pair!r}")
        query.label(key, value)
    if args.status_gte is not None:
        query.status_between(gte=args.status_gte)
    if args.dropped is not None:
        query.with_dropped_fields(args.dropped or None)
    for aggregation in args.agg or []:
        if aggregation == "over-time":
            query.over_time(args.interval)
        elif aggregation == "duration":
            query.percentiles("event.duration_ms")
        elif aggregation.startswith("by-"):
            # The field path, as it appears in the mapping. No translation:
            # by-log_origin_file_name would have to guess where the dots go.
            query.count_by(aggregation[3:], size=args.agg_size)
        else:
            raise QueryError(f"unknown aggregation {aggregation!r}")
    query.page(args.size)
    print(json.dumps(query.body(), indent=2))
    for note in query.notes():
        print(f"note: {note}", file=sys.stderr)
    return OK


def cmd_ingest(args: argparse.Namespace) -> int:
    templates = _load(args)
    strategy = Strategy(args.strategy)
    mapping = args.mapping or STRATEGY_MAPPING[strategy]
    field_map = _field_map(templates, mapping)
    events = _read_events(Path(args.source))
    report, results = run(events, field_map, strategy)
    print(f"{report.total} events through {mapping} under {strategy.value}\n")
    print(f"  accepted          {report.accepted}")
    print(f"  rejected          {report.rejected}")
    print(f"  held back         {report.diverted}")
    print(
        f"  silent losses     {report.silently_lost_values} values in "
        f"{report.documents_with_silent_loss} documents"
    )
    if report.silent_field_losses:
        print("\n  not indexed, and the write still succeeded:")
        for path, count in report.silent_field_losses.most_common():
            print(f"    {path:<30} {count}")
    if report.repairs:
        print("\n  repaired before sending:")
        for path, count in report.repairs.most_common():
            print(f"    {path:<30} {count}")
    if report.routed_keys:
        print(f"\n  routed into the catch-all: {', '.join(sorted(report.routed_keys))}")
    if report.rejections:
        print("\n  rejected by the cluster:")
        for reason, count in report.rejections.most_common():
            print(f"    {reason:<40} {count}")
    if args.show_losses:
        print("\n  every silent loss, with its reason:")
        for result in results:
            for loss in result.not_indexed:
                print(f"    {result.event_id} {loss.reason}")
    if args.dead_letter:
        held = [r for r in results if r.diverted]
        Path(args.dead_letter).write_text(
            "".join(json.dumps({"event": r.event_id, "reason": r.rejection}) + "\n" for r in held),
            encoding="utf-8",
        )
        print(f"\n  {len(held)} events written to {args.dead_letter}")
    if args.operations:
        Path(args.operations).write_text(
            "".join(json.dumps(op) + "\n" for op in bulk_operations(results, args.alias)),
            encoding="utf-8",
        )
        print(f"  bulk operations written to {args.operations}")
    return FINDINGS if report.silently_lost_values else OK


def cmd_compare(args: argparse.Namespace) -> int:
    templates = _load(args)
    events = _read_events(Path(args.source))
    print(f"{len(events)} events, three strategies, one question: what went missing quietly\n")
    header = (
        f"{'':<18}{'accepted':>9}{'rejected':>9}{'held back':>11}"
        f"{'lost quietly':>14}{'repaired':>10}"
    )
    print(header)
    print("-" * len(header))
    rows = []
    for strategy in Strategy:
        field_map = _field_map(templates, STRATEGY_MAPPING[strategy])
        report, _ = run(events, field_map, strategy)
        rows.append((strategy, report))
        print(
            f"{strategy.value:<18}{report.accepted:>9}{report.rejected:>9}"
            f"{report.diverted:>11}{report.silently_lost_values:>14}"
            f"{sum(report.repairs.values()):>10}"
        )
    print("\nwhat each column means for the person reading a dashboard later:")
    print("  rejected      the write failed and the producer knows")
    print("  held back     never sent, and the event is still on disk here")
    print("  lost quietly  indexed with a 201, the field absent from every query")
    worst = max(rows, key=lambda row: row[1].silently_lost_values)
    print(
        f"\n{worst[0].value} loses {worst[1].silently_lost_values} values with a successful "
        f"response, across {worst[1].documents_with_silent_loss} documents. _ignored is the "
        f"only place they are recorded, and it holds the field name, never the value."
    )
    return OK


def cmd_lifecycle(args: argparse.Namespace) -> int:
    templates = _load(args)
    for template in templates.installed_templates():
        name = template.policy_name
        if name is None or name not in templates.policies:
            continue
        policy = Policy.load(name, templates.policies[name])
        composed = templates.compose(template.name)
        primaries = int(composed.settings.get("index.number_of_shards", 1) or 1)
        replicas = int(composed.settings.get("index.number_of_replicas", 1))
        print(
            f"{name}  writes through {template.write_alias}  "
            f"{primaries} primary, {replicas} replica"
        )
        for line in policy.timeline():
            print(f"  {line}")
        try:
            ceiling = policy.ceiling(primaries=primaries, replicas=replicas)
        except LifecycleError as exc:
            print(f"  no ceiling: {exc}")
        else:
            print(f"  ceiling: {ceiling}")
        print("  min_age runs from the rollover date, not from index creation\n")
    return OK


def cmd_bootstrap(args: argparse.Namespace) -> int:
    templates = _load(args)
    requests = []
    for step in templates.bootstrap_steps:
        kind = step["kind"]
        name = step["name"]
        if kind == "ilm_policy":
            body = json.loads((templates.directory / step["file"]).read_text(encoding="utf-8"))
            requests.append((f"PUT _ilm/policy/{name}", body))
        elif kind == "component_template":
            body = json.loads((templates.directory / step["file"]).read_text(encoding="utf-8"))
            requests.append((f"PUT _component_template/{name}", body))
        elif kind == "index_template":
            body = json.loads((templates.directory / step["file"]).read_text(encoding="utf-8"))
            requests.append((f"PUT _index_template/{name}", body))
        elif kind == "write_index":
            # is_write_index matters here and nowhere else. An alias over more
            # than one index refuses a write unless exactly one of them claims
            # it, and the rollover action is what moves the claim.
            requests.append((f"PUT {name}", {"aliases": {step["alias"]: {"is_write_index": True}}}))
    for target, body in requests:
        print(f"# {target}")
        print(json.dumps(body, indent=2))
        print()
    print(f"# {len(requests)} requests, in the order Elasticsearch needs them")
    return OK


# ----- wiring ---------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsearch",
        description="Index templates, an ILM policy and a query builder for structured logs.",
    )
    parser.add_argument("--version", action="version", version=f"logsearch {__version__}")
    parser.add_argument(
        "--indices", help="a directory of template files other than the shipped one"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("lint", help="check the template files").set_defaults(func=cmd_lint)

    fields = subparsers.add_parser("fields", help="the composed mapping, field by field")
    fields.add_argument("mapping", nargs="?", default="logs-app")
    fields.add_argument("--grep", help="only paths containing this")
    fields.set_defaults(func=cmd_fields)

    explain = subparsers.add_parser("explain", help="what one field can and cannot do")
    explain.add_argument("field")
    explain.add_argument("--mapping", default="logs-app")
    explain.set_defaults(func=cmd_explain)

    query = subparsers.add_parser("query", help="emit a search body")
    query.add_argument("--mapping", default="logs-app")
    query.add_argument("--since", help="a date or a relative time like now-1h")
    query.add_argument("--until", default="now")
    query.add_argument("--service", action="append")
    query.add_argument("--level", help="this severity and above")
    query.add_argument("--message", help="a match clause, the only scored one")
    query.add_argument("--label", action="append", metavar="KEY=VALUE")
    query.add_argument("--status-gte", type=int)
    query.add_argument(
        "--dropped",
        nargs="?",
        const="",
        metavar="FIELD",
        help="only documents where ignore_malformed threw a field away",
    )
    query.add_argument("--agg", action="append", metavar="by-service.name|over-time|duration")
    query.add_argument("--agg-size", type=int, default=10)
    query.add_argument("--interval", default="5m")
    query.add_argument("--size", type=int, default=50)
    query.set_defaults(func=cmd_query)

    ingest = subparsers.add_parser("ingest", help="run events through the ingest path")
    ingest.add_argument("--source", default="fixtures/events.jsonl")
    ingest.add_argument(
        "--strategy", default=Strategy.STRICT.value, choices=[s.value for s in Strategy]
    )
    ingest.add_argument("--mapping", help="override the mapping this strategy implies")
    ingest.add_argument("--alias", default="logs-app")
    ingest.add_argument("--show-losses", action="store_true")
    ingest.add_argument("--dead-letter", metavar="PATH")
    ingest.add_argument("--operations", metavar="PATH", help="write the bulk body here")
    ingest.set_defaults(func=cmd_ingest)

    compare = subparsers.add_parser("compare", help="the three strategies side by side")
    compare.add_argument("--source", default="fixtures/events.jsonl")
    compare.set_defaults(func=cmd_compare)

    subparsers.add_parser("lifecycle", help="phases and the ceiling they imply").set_defaults(
        func=cmd_lifecycle
    )

    subparsers.add_parser("bootstrap", help="the requests that install all of it").set_defaults(
        func=cmd_bootstrap
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (TemplateError, FieldUsageError, QueryError, StrategyMismatch, LifecycleError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return REFUSED
    except OSError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return REFUSED


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
