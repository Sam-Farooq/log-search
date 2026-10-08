# fixtures

Every line in these files was written for this repository. Nothing was captured
from a service, a cluster, an agent or a log shipper. No part of this repo has
ever been pointed at a running system. The only Elasticsearch it is ever pointed
at is the service container declared in `.github/workflows/ci.yml`, and that
workflow has not run, so nothing here has touched a cluster.

They exist because the mapping problems worth writing about are rare in a sample
of real traffic and are the whole content here, so they are present on purpose
and in known quantities.

## events.jsonl

42 application log events, shaped the way a service with an ECS-style logger
would emit them. 23 are ordinary. The other 19 each carry one specific problem,
counted here so a test can assert the totals rather than trusting a run:

| how many | what is wrong with them | the mapping question it asks |
|---|---|---|
| 5 | `event.duration_ms` is `"1.4s"`, `"250ms"`, `"2m"`, `"0.9s"`, `"480ms"` | a field that is a long in one service and a string with a unit in another |
| 2 | `http.response.status_code` is `"200"` and `"503"` | the conflict Elasticsearch coerces away without telling anyone |
| 2 | `event.duration_ms` is `{"value": 1400, "unit": "ms"}` | an object sent to a scalar field, which `ignore_malformed` does not cover |
| 3 | keys that are in no template: `tenant`, `retry_count`, `shard_hint`, `k8s.*` | what `dynamic` is for, and where unknown keys should go instead |
| 2 | `labels.exp_*` keys with generated names, 3 on one event and 4 on the other, 7 distinct | the arbitrary key set that reaches a mapping explosion |
| 1 | a 1448 character `message` | `ignore_above` on the keyword half of a multi-field |
| 1 | `client.ip` is `10.0.0.300` | a value that looks like its type and is not |
| 1 | `@timestamp` is `2026-03-07 13:30:00 PST` | a format the field does not declare |
| 1 | `http.response.status_code` is `70000` | in range for a long, out of range for a short |
| 1 | `labels` nested four deep | `depth_limit` on a flattened field |

The `exp_*` keys are invented hexadecimal, and the two events share none of
them, which is the point: an unbounded key set is unbounded because nobody is
choosing the keys.

## audit-events.jsonl

8 audit records for the `logs-audit` mapping, which has no catch-all. Six are
clean. One carries `request_body`, one carries `labels`, and both are rejected,
which is the behaviour that template was written to have.

## type-cases.json

The value and field pairs the `live`-marked tests are written to replay against
the CI service container, to check the verdicts in `logsearch/conflicts.py`
against the parser they are a model of. A disagreement there would mean this
repository is wrong about Elasticsearch, and that test is the only thing that
could say so. It has not run.
