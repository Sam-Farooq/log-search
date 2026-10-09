# log-search

Log search over structured events in Elasticsearch 8. The index templates and
the ILM policies are files, and they are the product: Python is the query
builder, the ingest path, and the checks that stop a bad mapping being
installed. Nothing here has run against a cluster. The only cluster it is ever
pointed at is the Elasticsearch service container that
`.github/workflows/ci.yml` declares, and that workflow has not run: this
repository has no remote and nothing has been pushed.

```
indices/                     ten JSON files, 12,971 bytes, the part that matters
  component-logs-settings.json   shards, refresh, the field limit, the index sort
  component-logs-base.json       timestamp, message, log, event, service, error
  component-logs-http.json       http, url, client, user_agent
  component-logs-labels.json     the flattened catch-all
  template-logs-app.json         composes the four, dynamic strict
  template-logs-audit.json       no catch-all, and that is the point
  template-logs-app-lenient.json the ignore_malformed variant, not installed
  ilm-logs-app.json              roll daily, delete at 30 days
  ilm-logs-audit.json            roll weekly, keep for a year
  bootstrap-order.json           the order Elasticsearch requires
logsearch/templates.py       composes component templates the way the cluster does
logsearch/fields.py          what each field can be asked, and what it cannot
logsearch/conflicts.py       what happens to a value the mapping cannot hold
logsearch/ingest.py          three strategies for that, run over the same events
logsearch/query.py           search bodies that only name fields that exist
logsearch/lifecycle.py       phase transitions, and the ceiling they imply
logsearch/lint.py            nineteen findings, before anything is installed
logsearch/client.py          the official client. The only file that connects
fixtures/                    42 events written for this repo, 19 of them wrong
```

## The field that is a string in one service and a number in another

This is the problem. One service sends `event.duration_ms: 1400` and another
sends `"1.4s"`, and the second one is a mapping conflict. There are three usual
answers and they fail differently, so the repository runs all three over the
same 42 events and counts the difference.

```bash
logsearch compare
```

```
                   accepted rejected  held back  lost quietly  repaired
-----------------------------------------------------------------------
strict                   31       11          0             1         0
ignore-malformed         40        2          0            14         0
normalize                36        0          6             1         5
```

- **rejected** is a failed write. The bulk item carries the error, the producer
  sees it, and the line is gone.
- **held back** never left the ingest path. The event is still on disk here.
- **lost quietly** is a document that indexed with a 201 and is missing a field
  from every query, every aggregation and every dashboard built on it.

The third column is the one worth arguing about, so it gets its own section.

## What ignore_malformed loses

`ignore_malformed: true` means a value the field's parser refuses is not
indexed, and the document is indexed anyway. The write returns 201. The value
is still in `_source`, so it reads back in a search hit and looks present. It
is absent from the inverted index and from doc_values, so:

- a term or range query over it does not match the document
- an aggregation over it does not count the document
- a dashboard panel built on either shows a smaller number and no gap

Fourteen values across thirteen of the forty-two events go that way, and the
only record of it is `_ignored`, a metadata field listing the names of the
fields that were dropped. Not the values. The values are in `_source` and in no
index, and there is no query that reaches them.

```bash
logsearch query --dropped event.duration_ms
```

The filter clause in the body it prints is the whole of it:

```json
{"term": {"_ignored": "event.duration_ms"}}
```

So the thing to understand about `ignore_malformed` is not that it loses data.
It is that it loses data **and returns success**, which means the loss is
discovered by someone asking why a chart looks low, weeks later, rather than by
the system that wrote the line.

Two more things about it that the setting's name does not suggest:

**It does not cover an object sent to a scalar field.** Two of the 42 events
send `event.duration_ms: {"value": 1400, "unit": "ms"}`, and those documents are
rejected under `ignore_malformed` exactly as they are under a strict mapping.
That is why the lenient column above reads 2 rejected rather than 0.

**It is not the only silent loss.** `ignore_above` on a keyword drops a value
that is too long, with a 201, and `ignore_malformed: false` does not prevent it.
One event here carries a 1448 character message; `message` is `text` with no
length limit and `message.raw` is a keyword capped at 1024, so that event is
searchable by a word in it and absent from every aggregation over messages. It
is the 1 in the strict and normalize columns, and `logsearch ingest` names the
field rather than rounding it to zero.

## The strategy this repo chose, and what it cost

Templates set `ignore_malformed` false everywhere, explicitly, at the index
level and on no field. The ingest path normalizes instead: it parses `"1.4s"` to
1400 and `"250ms"` to 250, routes unknown keys into the catch-all, and holds
back what it cannot repair.

```bash
logsearch ingest --strategy normalize --dead-letter held.jsonl
```

5 values repaired, 6 events held back, 36 sent, and the 6 are on disk with the
reason attached rather than in the index with a field missing.

What that costs, and it is not small:

- **A producer-side dependency.** The repair lives in whatever writes the logs,
  so a mapping change needs a deploy on that side rather than a template PUT.
- **A dead letter nobody drains.** Six events in a file is six events nobody
  looks at. A rejected write at least surfaces as an error rate.
- **It is a model, not the parser.** `logsearch/conflicts.py` is this repo's
  idea of how Elasticsearch parses a value. Where the two disagree, this repo is
  wrong, and `fixtures/type-cases.json` plus the tests marked `live` are the only
  thing that could say so: 18 value and field pairs to replay against the CI
  service container, where a verdict of `malformed` has to be rejected by the
  strict mapping and land in `_ignored` under the lenient one. Those tests have
  not run.

## keyword or text, and why `message` is both

A `keyword` field is indexed as one term, so it can be filtered exactly and
grouped in an aggregation. A `text` field is analysed into words, so it can be
searched for a word inside it and cannot be grouped at all, because aggregating
text needs fielddata and that loads every term in the field onto the heap.

A log message needs both, so it is a multi-field: one JSON value, two index
structures, two names.

```bash
logsearch explain message
```

```
message
  type          text (leaf), from logs-base
  searchable    yes
  aggregatable  no
  multi-fields  message.raw (keyword)
  term          refused: message is text, so its values were analysed before being
                indexed. A term query is not analysed, so any term carrying a capital
                or punctuation matches nothing. Use message.raw for an exact match,
                or match() to search it.
  match         ok
  agg           ok -> message.raw
```

(two lines of that output are left out here, and the refusals are wrapped)

The refusal is the useful part. `{"term": {"message": "Handled"}}` is a valid
query that returns zero hits and a 200, because the indexed terms were
lowercased and the query term was not. A live test is written to run both halves
of that against a cluster: the term query finds nothing, the match query finds
the documents. It needs a cluster, so it has not run.

Multi-fields are not free. They are extra entries in the mapping and they count
against `index.mapping.total_fields.limit`.

## The catch-all, and the mapping explosion it exists to prevent

With `dynamic: true`, which is the default, a key that arrives is added to the
mapping and stays there. The mapping lives in the cluster state, every node
holds the cluster state, and the key came from a request body. That is the whole
mechanism: a tenant id in a label, or an experiment flag with a generated name,
and the mapping grows by one field per distinct key forever until writes start
failing on the field limit.

`logs-app` sets `dynamic: strict`, so an unmapped key is a rejected document,
and declares one `flattened` field to catch them:

```json
"labels": {"type": "flattened", "depth_limit": 3, "ignore_above": 256}
```

A flattened field is one entry in the mapping with an unbounded set of keys
underneath it. Thirteen distinct keys arrive in the fixtures, seven of them
`exp_*` keys carried by two events, three on one and four on the other, sharing
none of their names, and the mapping gains nothing. `labels.tenant` is queryable
as a term and groupable in an aggregation.

The cost, stated plainly: **every value under a flattened field is indexed as a
keyword.** `labels.retry_count: 3` is the string `3`. It cannot be
range-queried, it cannot be averaged, and a histogram over it is a histogram of
strings. The query builder refuses a range on a flattened key and says to
promote the key into the mapping instead. There is also a depth limit of 3, and
one fixture event nests four deep to prove it fails.

`logs-audit` has no catch-all at all, and `dynamic: strict` with nothing to
catch unknown keys means an unexpected field rejects the write. That is correct
there and wrong for application logs: an audit record comes from one internal
library so the field set is closed, and an arbitrary key reaching that index
came from a request body. A mapping explosion in the index you are least allowed
to delete is not recoverable. Two of the eight audit fixtures are rejected on
purpose.

The combination to avoid is `dynamic: false` with no catch-all, which keeps the
unknown key in `_source` and out of the index. The log line reads back fine in a
hit and matches nothing. `logsearch lint` fails on it.

## The alias with a write index

Nothing writes to an index name here. Both pipelines write to an alias, and
exactly one index behind that alias carries `is_write_index: true`.

```bash
logsearch bootstrap
```

```
# PUT logs-app-000001
{"aliases": {"logs-app": {"is_write_index": true}}}
```

That flag is what lets a rollover happen without the writer knowing. ILM creates
`logs-app-000002`, moves the flag, and the producer keeps posting to `logs-app`.
An alias over more than one index with none of them claiming the write refuses
every write, and that error arrives at the producer rather than anywhere near
this repository. A live test is written to roll the alias and then write through
it again, checking the new index receives the document.

The bootstrap order is not a preference either. A composed index template is
rejected at PUT time when `composed_of` names a component that does not exist,
so components go first. An ILM policy named by a template is **not** checked at
PUT time, so getting that order wrong installs a template cleanly and leaves
every index it creates with no lifecycle at all.

## Retention, and the arithmetic nobody does

```bash
logsearch lifecycle
```

```
logs-app  writes through logs-app  1 primary, 1 replica
  hot     on rollover            rollover, set_priority
  warm    2d after rollover      forcemerge, set_priority
  cold    7d after rollover      readonly, set_priority
  delete  30d after rollover     delete
  ceiling: 31 live indices at 30gb per primary is 930gb of primaries and 1860gb on disk
  min_age runs from the rollover date, not from index creation
```

Thirty days of retention at a daily rollover is 31 live indices, because the
write index has not rolled yet. `max_primary_shard_size` is per primary, so the
per index figure multiplies by the shard count, and replicas multiply the disk.
Every number there is division on two values in `ilm-logs-app.json`.

The audit policy rolls weekly rather than daily for the same reason, and the
arithmetic is why: a year of retention at a daily rollover is 366 indices, each
with its own shard, for the same bytes. Weekly gives 54 indices and 1080gb of
primaries.

`min_age` is measured from the rollover date for an index that has rolled over,
not from its creation date. A warm transition at `2d` therefore does not fire on
an index that is still the write index, which is the behaviour you want and not
the one the field name suggests.

## The checks

```bash
logsearch lint
```

```
NOTE  total_fields     logs-app: 55 fields of 200, 145 spare, counting leaf fields,
                       object nodes and multi-fields
NOTE  ceiling          logs-app: 31 live indices at 30gb per primary is 930gb of
                       primaries and 1860gb on disk
NOTE  uninstalled_wins logs-app-lenient: not installed, and its priority 400 is above
                       logs-app. Installing it would take over those patterns at the
                       next rollover without an error

3 index templates, 4 components, 2 policies: 0 errors, 7 notes
```

Nineteen finding codes, and with one exception every one of them is a mistake a
cluster accepts. The exception is a typo in `composed_of`, which Elasticsearch rejects
itself. The rest install cleanly and go wrong later: `dynamic` left at true, a
`_meta.catch_all` that names a field the composed mapping does not have,
`dynamic: false` with no catch-all, `ignore_malformed` set without permission in
`_meta`, a date format the value checker cannot model, the `search_after`
tiebreaker going missing from a component, two templates matching one pattern at
one priority, a template naming a policy with no file, `forcemerge` in the hot
phase with no rollover, phases whose `min_age` runs backwards, and a bootstrap
order that would PUT a composed template before its components.

The field count is a note rather than a limit fitted to it. The counting rule is
leaf fields plus object nodes plus multi-fields, metadata fields excluded, and
Elasticsearch's own accounting for `total_fields.limit` can differ by the root
object. So the limit is 200 against a count of 55: headroom instead of
precision. What that gives up is early warning. A limit that sat at 60 would
fail the build on the next component that added five fields, and 200 will not
notice a hundred arriving one at a time. A live test is written for the
direction that matters, creating the index with a limit of 10 and checking the
cluster refuses it, and only a cluster can answer it.

## Running it

```bash
python3.11 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

logsearch lint                       # the template files. 0 errors, 7 notes
logsearch lifecycle                  # phases and the ceiling they imply
logsearch compare                    # the three strategies over 42 events
logsearch fields logs-app --grep url # the composed mapping, field by field
logsearch explain log.level          # one field, and every clause it refuses
logsearch bootstrap                  # the 10 requests that install all of it
logsearch ingest --strategy ignore-malformed --show-losses
logsearch query --since now-1h --service checkout-api --level warn \
  --message timeout --agg by-url.path --agg over-time
```

Exit codes, because this is only useful if a build can act on it:

| code | meaning |
|---|---|
| 0 | nothing to report |
| 1 | the linter found an error, or the ingest report lost a value quietly |
| 2 | refused: usage, an unreadable file, an unknown template or field |

`logsearch ingest --strategy strict` exits 1, not 0, and that is deliberate. One
message still loses its keyword half to `ignore_above`, and a gate that calls
that zero is not a gate.

## Tests

```bash
pytest -q                 # 151 tests, no cluster, no network, no key
ruff check logsearch tests && ruff format --check .
```

The templates are JSON, the field walk is a function over them, the value checks
are pure and the query builder returns a dict, so the default suite needs
nothing running. What has actually been run is exactly that: both lines above on
one macOS 27.0.1 laptop under Python 3.11.17, 157 passed and 27 deselected,
plus every command in the section above it. Nothing has run on a hosted runner,
and nothing has run against a cluster.

157 of those tests, up from 151: four of them compare the README against the
workflow rather than exercising the CLI, because the claim that CI runs every
documented command is the kind that nothing else could contradict.

27 more tests are marked `live` and deselected by default:

```bash
ELASTICSEARCH_URL=http://localhost:9200 pytest -m live
```

The `cluster` job in `.github/workflows/ci.yml` declares an Elasticsearch 8.17.3
service container for them. That job has never executed: the repository has no
remote, nothing has been pushed, and no Elasticsearch has been started by
anything here. The workflow file is configuration, not a result. Those tests are
the only ones here that could tell whether this repository is right about
Elasticsearch rather than merely consistent with itself, and they carry the
things no offline assertion reaches: the composed mapping being accepted as
written, the 18 rows of the type table agreeing with the real parser, the term
query on an analysed field finding nothing while the match query finds
documents, the aggregation on `message` being refused with `Fielddata is
disabled` while `message.raw` returns buckets, and the write index moving under
an unchanged alias.

The offline job also runs every command in this README and checks two exit
codes, because a documented exit code nobody runs drifts.

## What this does not do

- **No data streams.** An alias with a write index and a rollover does the same
  job and is explicit about which index is which, which is the point of a repo
  about mappings. A data stream would hide the thing being explained, and it
  would also forbid updates and require `create` for every write.
- **No ingest pipelines.** The normalization runs in Python, in a library the
  producer imports, so it is testable without a cluster and a repair is visible
  in a stack trace. The cost is that it cannot fix a producer that does not use
  it, which an ingest pipeline could.
- **No runtime fields.** They would let an unmapped value be queried without a
  reindex, at query time cost, and they are the honest answer to some of what is
  called a mapping conflict here. Not implemented.
- **No searchable snapshots and no frozen tier.** Those need a snapshot
  repository, and there is no object store in this repo to point one at.
- **No security, no TLS, no API keys.** The service container is declared with
  `xpack.security.enabled: false`. Nothing here has a credential, which is also
  why nothing here could reach a real cluster by accident.
- **No analyzers of its own.** `message` uses the standard analyser. No
  synonyms, no stemming, no custom tokenizer, so a search for `timeouts` does
  not find `timeout`.
- **No Kibana, no dashboards, no alerting.** The query builder emits bodies. What
  reads them is not this repo's problem.

## Where it can still be wrong

- **`conflicts.py` is a model of a parser.** It covers integers with their
  bounds, floats, dates in two formats, ip, boolean, keyword with
  `ignore_above`, text and flattened with its depth limit. It does not model
  analysis, geo types, dense vectors, or the coercion corners of
  `scaled_float`. A field type it does not know is passed through as acceptable,
  which is the wrong direction to be wrong in, and `logsearch lint` fails on an
  unmodelled date format for exactly that reason.
- **The field count is this repo's rule, not the cluster's.** See the headroom
  note above.
- **`search_after` without a point in time.** The sort carries `event.id` as a
  unique tiebreaker, which is what makes paging work at all, but documents
  indexed between two pages still shift the sort, so a row can be seen twice or
  missed. A PIT would fix it and holds segments open on every shard for as long
  as it lives. This is log search, so the tiebreaker won.
- **`create` with the event id de-duplicates a retry and not a replay.** It is
  idempotent within one index. After a rollover the same id lands in the new
  write index and the 409 never comes.
- **One primary shard per index.** It makes the rollover size the index size,
  which is the whole reason the ceiling arithmetic is one multiplication. It
  also caps indexing throughput for one index at one shard's worth, and
  `max_primary_shard_size` is the only knob left.
- **`refresh_interval: 10s`.** A log line is not searchable for up to ten
  seconds after the write succeeds. That is the trade for a tenth of the segment
  churn, and it is the wrong default for anyone debugging a live incident by
  tailing a query.
- **Nothing here has run against any cluster, production or otherwise.** Every
  number in this
  README is either arithmetic over the template files or the output of a command
  in it over `fixtures/`, and the fixtures were written for this repository
  rather than captured from anything. `fixtures/README.md` says which file
  carries which problem and how many of each.
