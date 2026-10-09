from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from logsearch.cli import FINDINGS, OK, REFUSED, main

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"


def documented_invocations(readme: str) -> list[str]:
    """The distinct `logsearch` commands the README's bash blocks tell a reader to run.

    Trailing `#` comments and backslash continuations are folded out, so each
    entry is the command a shell would receive. First-appearance order with
    duplicates dropped, because `logsearch lint` is shown twice and is one
    command.
    """
    commands: list[str] = []
    in_bash = False
    pending = ""
    for raw in readme.splitlines():
        if raw.startswith("```"):
            in_bash = raw.strip() == "```bash"
            pending = ""
            continue
        if not in_bash:
            continue
        line = raw.strip()
        if not pending and not line.startswith("logsearch "):
            continue
        pending = f"{pending} {line}"
        if pending.endswith("\\"):
            pending = pending[:-1]
            continue
        commands.append(" ".join(pending.split(" #")[0].split()))
        pending = ""
    return list(dict.fromkeys(commands))


def offline_job_invocations(workflow: str) -> list[str]:
    """The distinct `logsearch` commands the workflow's `offline` job runs.

    Shell decoration is cut at the first redirection or operator, so a step that
    captures an exit code compares equal to the bare command the README shows.
    """
    lines = workflow.splitlines()
    start = lines.index("  offline:")
    end = next(
        (index for index in range(start + 1, len(lines)) if re.match(r"^  \S", lines[index])),
        len(lines),
    )
    commands: list[str] = []
    for raw in lines[start:end]:
        line = raw.strip().removeprefix("- ").removeprefix("run: ").strip()
        if not line.startswith("logsearch "):
            continue
        commands.append(" ".join(re.split(r"\s(?:\d*>|&&|\|\|)", line)[0].split()))
    return list(dict.fromkeys(commands))


def test_the_package_and_the_project_agree_about_the_version():
    """Two places hold it, so one test holds them together."""
    from logsearch import __version__

    pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    assert f'version = "{__version__}"' in pyproject
    assert __version__ == "0.13.2"


def test_lint_exits_zero_on_the_shipped_files(capsys):
    assert main(["lint"]) == OK
    out = capsys.readouterr().out
    assert "0 errors, 7 notes" in out
    assert "3 index templates, 4 components, 2 policies" in out


def test_lint_exits_one_when_a_file_is_wrong(tmp_path, capsys):
    directory = tmp_path / "indices"
    directory.mkdir()
    for source in (Path(__file__).resolve().parent.parent / "indices").glob("*.json"):
        body = json.loads(source.read_text(encoding="utf-8"))
        if source.name == "template-logs-app.json":
            body["template"]["mappings"]["dynamic"] = True
        (directory / source.name).write_text(json.dumps(body), encoding="utf-8")
    assert main(["--indices", str(directory), "lint"]) == FINDINGS
    assert "ERROR dynamic" in capsys.readouterr().out


def test_an_unreadable_indices_directory_is_refused(tmp_path, capsys):
    assert main(["--indices", str(tmp_path / "nope"), "lint"]) == REFUSED
    assert "refused:" in capsys.readouterr().err


def test_fields_counts_what_it_showed_and_what_it_did_not(capsys):
    assert main(["fields", "logs-app", "--grep", "http"]) == OK
    out = capsys.readouterr().out
    assert "http.response.status_code" in out
    assert "shown of 55 counted against a limit of 200" in out
    assert "dynamic=strict" in out


def test_explain_prints_a_verdict_per_clause(capsys):
    assert main(["explain", "message"]) == OK
    out = capsys.readouterr().out
    assert "multi-fields  message.raw (keyword)" in out
    assert "term          refused:" in out
    assert "agg           ok -> message.raw" in out


def test_explain_on_an_unmapped_field_says_what_a_query_would_do(capsys):
    assert main(["explain", "user.email"]) == OK
    out = capsys.readouterr().out
    assert "is not in the logs-app mapping" in out
    assert "returns 200 and matches nothing" in out


def test_explain_knows_a_flattened_key_is_not_a_field(capsys):
    assert main(["explain", "labels.tenant"]) == OK
    out = capsys.readouterr().out
    assert "is a key inside the flattened field labels" in out


def test_query_emits_valid_json_and_notes_on_stderr(capsys):
    assert (
        main(
            [
                "query",
                "--since",
                "now-1h",
                "--service",
                "checkout-api",
                "--level",
                "warn",
                "--message",
                "timeout",
                "--label",
                "tenant=acme",
                "--status-gte",
                "500",
                "--agg",
                "by-url.path",
                "--agg",
                "over-time",
                "--size",
                "25",
            ]
        )
        == OK
    )
    captured = capsys.readouterr()
    body = json.loads(captured.out)
    assert body["size"] == 25
    assert len(body["query"]["bool"]["filter"]) == 5
    assert body["query"]["bool"]["must"][0]["match"]["message"]["query"] == "timeout"
    assert set(body["aggs"]) == {"by_url_path", "over_time"}
    assert "sorts error below info" in captured.err


def test_a_label_without_a_value_is_refused(capsys):
    assert main(["query", "--label", "tenant"]) == REFUSED
    assert "wants key=value" in capsys.readouterr().err


def test_a_query_on_the_audit_mapping_refuses_a_label(capsys):
    assert main(["query", "--mapping", "logs-audit", "--label", "tenant=acme"]) == REFUSED
    assert "not in the logs-audit mapping" in capsys.readouterr().err


def test_query_can_ask_for_what_ignore_malformed_dropped(capsys):
    assert main(["query", "--dropped", "event.duration_ms"]) == OK
    body = json.loads(capsys.readouterr().out)
    assert body["query"]["bool"]["filter"] == [{"term": {"_ignored": "event.duration_ms"}}]


def test_ingest_exits_one_when_anything_was_lost_quietly(capsys):
    code = main(["ingest", "--source", str(FIXTURES / "events.jsonl"), "--strategy", "strict"])
    out = capsys.readouterr().out
    assert "42 events through logs-app under strict" in out
    assert "accepted          31" in out
    assert "message.raw" in out
    # One silent loss is still a silent loss, so the exit code is not zero.
    assert code == FINDINGS


def test_ingest_writes_a_dead_letter_file_and_a_bulk_body(tmp_path, capsys):
    dead = tmp_path / "held.jsonl"
    operations = tmp_path / "bulk.ndjson"
    code = main(
        [
            "ingest",
            "--source",
            str(FIXTURES / "events.jsonl"),
            "--strategy",
            "normalize",
            "--dead-letter",
            str(dead),
            "--operations",
            str(operations),
        ]
    )
    assert code == FINDINGS
    held = [json.loads(line) for line in dead.read_text(encoding="utf-8").splitlines()]
    assert len(held) == 6
    assert all(entry["reason"] for entry in held)
    lines = operations.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 36 * 2
    assert json.loads(lines[0])["create"]["_index"] == "logs-app"
    assert "6 events written to" in capsys.readouterr().out


def test_a_strategy_the_mapping_does_not_implement_is_refused(capsys):
    code = main(
        [
            "ingest",
            "--source",
            str(FIXTURES / "events.jsonl"),
            "--strategy",
            "ignore-malformed",
            "--mapping",
            "logs-app",
        ]
    )
    assert code == REFUSED
    assert "cannot be run under the ignore-malformed strategy" in capsys.readouterr().err


def test_a_broken_source_line_is_refused_with_its_number(tmp_path, capsys):
    source = tmp_path / "events.jsonl"
    source.write_text('{"event":{"id":"e-1"}}\nnot json\n', encoding="utf-8")
    assert main(["ingest", "--source", str(source)]) == REFUSED
    assert "line 2" in capsys.readouterr().err


def test_compare_puts_the_three_strategies_in_one_table(capsys):
    assert main(["compare"]) == OK
    out = capsys.readouterr().out
    assert "42 events, three strategies" in out
    for line in out.splitlines():
        if line.startswith("ignore-malformed"):
            assert line.split()[1:] == ["39", "3", "0", "13", "0"]
            break
    else:  # pragma: no cover
        pytest.fail("no ignore-malformed row")


def test_lifecycle_prints_both_policies_with_their_ceilings(capsys):
    assert main(["lifecycle"]) == OK
    out = capsys.readouterr().out
    assert "930gb of primaries and 1860gb on disk" in out
    assert "1080gb of primaries and 2160gb on disk" in out
    assert out.count("min_age runs from the rollover date") == 2


def test_bootstrap_emits_one_request_per_step_in_order(capsys):
    assert main(["bootstrap"]) == OK
    out = capsys.readouterr().out
    targets = [line[2:] for line in out.splitlines() if line.startswith("# ")]
    assert targets[:2] == ["PUT _ilm/policy/logs-app", "PUT _ilm/policy/logs-audit"]
    assert "PUT _component_template/logs-base" in targets
    assert targets.index("PUT _component_template/logs-labels") < targets.index(
        "PUT _index_template/logs-app"
    )
    assert "PUT logs-app-000001" in targets
    assert '"is_write_index": true' in out
    assert "10 requests" in targets[-1]


def test_every_documented_invocation_is_in_the_offline_ci_job():
    """A documented command no build runs rots, so the offline job runs all of them.

    Eleven distinct commands, in the form the README writes them. The workflow
    has never executed, so this is the only thing enforcing the correspondence.
    """
    documented = documented_invocations(README.read_text(encoding="utf-8"))
    offline = offline_job_invocations(WORKFLOW.read_text(encoding="utf-8"))
    assert len(documented) == 11
    assert [command for command in documented if command not in offline] == []


def test_a_command_the_readme_gains_alone_fails_that_check():
    """The check above has to fail on a README the workflow does not cover.

    Before this existed the offline job ran five of the eleven and the README
    said it ran all of them, which no assertion could contradict.
    """
    doctored = README.read_text(encoding="utf-8") + "\n```bash\nlogsearch explain client.ip\n```\n"
    documented = documented_invocations(doctored)
    offline = offline_job_invocations(WORKFLOW.read_text(encoding="utf-8"))
    assert documented[-1] == "logsearch explain client.ip"
    assert [command for command in documented if command not in offline] == [
        "logsearch explain client.ip"
    ]


def test_a_step_the_offline_job_loses_fails_that_check():
    """And it has to fail in the other direction, on a workflow missing a step."""
    step = "      - run: logsearch explain log.level\n"
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert step in workflow
    offline = offline_job_invocations(workflow.replace(step, ""))
    documented = documented_invocations(README.read_text(encoding="utf-8"))
    assert [command for command in documented if command not in offline] == [
        "logsearch explain log.level"
    ]


def test_the_offline_job_asserts_the_non_zero_exit_codes_the_readme_documents():
    """Four assertions over the two non-zero codes in the README's table."""
    documented_codes = set(re.findall(r"^\| (\d) \|", README.read_text(encoding="utf-8"), re.M))
    asserted = re.findall(r'test "\$code" = "(\d)"', WORKFLOW.read_text(encoding="utf-8"))
    assert documented_codes == {"0", "1", "2"}
    assert set(asserted) == documented_codes - {"0"}
    assert len(asserted) == 4
