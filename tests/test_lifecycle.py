from __future__ import annotations

import pytest

from logsearch.lifecycle import (
    LifecycleError,
    Policy,
    duration_in_days,
    size_in_gb,
)


@pytest.fixture(scope="module")
def app_policy(templates) -> Policy:
    return Policy.load("logs-app", templates.policies["logs-app"])


@pytest.fixture(scope="module")
def audit_policy(templates) -> Policy:
    return Policy.load("logs-audit", templates.policies["logs-audit"])


def test_durations_and_sizes_parse_the_way_elasticsearch_writes_them():
    assert duration_in_days("30d") == 30
    assert duration_in_days("12h") == 0.5
    assert duration_in_days("1440m") == 1
    assert size_in_gb("30gb") == 30
    assert size_in_gb("1tb") == 1024
    assert size_in_gb("512mb") == 0.5
    with pytest.raises(LifecycleError, match="not an Elasticsearch time value"):
        duration_in_days("2 weeks")
    with pytest.raises(LifecycleError, match="not an Elasticsearch byte value"):
        size_in_gb("30 gigs")


def test_the_app_policy_has_four_phases_in_order(app_policy):
    assert [p.name for p in app_policy.phases] == ["hot", "warm", "cold", "delete"]
    assert app_policy.phase("hot").min_age_days == 0
    assert app_policy.phase("warm").min_age_days == 2
    assert app_policy.phase("delete").min_age_days == 30
    assert app_policy.out_of_order_phases() == []
    assert app_policy.phase("cold").action_names == ["readonly", "set_priority"]


def test_the_ceiling_is_arithmetic_from_the_policy(app_policy):
    ceiling = app_policy.ceiling(primaries=1, replicas=1)
    # 30 days kept, rolling daily, plus the write index that has not rolled.
    assert ceiling.live_indices == 31
    assert ceiling.per_index_gb == 30
    assert ceiling.primary_gb == 930
    assert ceiling.on_disk_gb == 1860


def test_shards_multiply_the_index_and_replicas_multiply_the_disk(app_policy):
    assert app_policy.ceiling(primaries=2, replicas=1).primary_gb == 1860
    assert app_policy.ceiling(primaries=1, replicas=0).on_disk_gb == 930
    assert app_policy.ceiling(primaries=1, replicas=2).on_disk_gb == 2790


def test_a_weekly_rollover_keeps_the_index_count_down_over_a_year(audit_policy):
    ceiling = audit_policy.ceiling(primaries=1, replicas=1)
    assert ceiling.live_indices == 54
    assert ceiling.primary_gb == 1080
    # Daily rollover over the same retention is the mistake this avoids: 366
    # indices, one shard each, for the same bytes.
    daily = Policy.load(
        "daily",
        {
            "phases": {
                "hot": {
                    "actions": {"rollover": {"max_age": "1d", "max_primary_shard_size": "20gb"}}
                },
                "delete": {"min_age": "365d", "actions": {"delete": {}}},
            }
        },
    )
    assert daily.ceiling().live_indices == 366


def test_a_policy_with_no_delete_phase_cannot_state_a_ceiling():
    policy = Policy.load(
        "forever",
        {"phases": {"hot": {"actions": {"rollover": {"max_age": "1d", "max_size": "50gb"}}}}},
    )
    assert policy.delete_after_days is None
    with pytest.raises(LifecycleError, match="Missing: delete min_age"):
        policy.ceiling()


def test_a_rollover_with_no_size_is_named_in_the_refusal():
    policy = Policy.load(
        "ageonly",
        {
            "phases": {
                "hot": {"actions": {"rollover": {"max_age": "1d"}}},
                "delete": {"min_age": "7d", "actions": {"delete": {}}},
            }
        },
    )
    with pytest.raises(LifecycleError, match="Missing: rollover size"):
        policy.ceiling()


def test_a_phase_that_arrives_already_past_its_min_age_is_reported():
    policy = Policy.load(
        "backwards",
        {
            "phases": {
                "hot": {
                    "actions": {"rollover": {"max_age": "1d", "max_primary_shard_size": "30gb"}}
                },
                "warm": {"min_age": "10d", "actions": {"forcemerge": {"max_num_segments": 1}}},
                "cold": {"min_age": "5d", "actions": {"readonly": {}}},
                "delete": {"min_age": "30d", "actions": {"delete": {}}},
            }
        },
    )
    problems = policy.out_of_order_phases()
    assert problems == ["cold min_age 5d is earlier than warm min_age 10d"]


def test_an_unknown_phase_name_is_refused():
    with pytest.raises(LifecycleError, match="tepid is not an ILM phase"):
        Policy.load("odd", {"phases": {"hot": {"actions": {}}, "tepid": {"actions": {}}}})


def test_a_policy_with_no_phases_is_refused():
    with pytest.raises(LifecycleError, match="has no phases"):
        Policy.load("empty", {"phases": {}})


def test_the_timeline_says_when_each_phase_fires(app_policy):
    lines = app_policy.timeline()
    assert lines[0].startswith("hot     on rollover")
    assert "2d after rollover" in lines[1]
    assert lines[3].startswith("delete  30d after rollover")
