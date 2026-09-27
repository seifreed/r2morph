# Adversarial Campaign Duration

## Scope

- Workflow run: `36280543038`
- Head commit: `5cbe1d43`
- Shards: 8 fixture shards
- Pass selection: all 22 corpus and extended maturity passes
- Measurement observed: 2026-09-27

## Remote Measurement

The five completed shards had these wall-clock durations, measured from the
GitHub job timestamps:

| Shard | Start (UTC) | End (UTC) | Duration |
|---:|---|---|---:|
| 1 | 23:47:49 | 01:10:27 | 82m38s |
| 2 | 23:47:49 | 01:12:40 | 84m51s |
| 5 | 23:47:49 | 01:11:11 | 83m22s |
| 6 | 23:47:49 | 01:18:49 | 91m00s |
| 7 | 23:48:25 | 01:12:50 | 84m25s |

At 02:47:01 UTC, shards 0, 3, and 4 were still executing the benchmark. No
terminal failure had been reported and no aggregate artifact existed. The
observed completed-shard mean was 85m15s; this is a lower bound for the full
campaign because the three active shards had not finished.

## Interpretation

The scheduled campaign is materially longer than the local single-fixture
baseline. This is sufficient evidence to investigate finer fixture sharding
or bounded parallel execution after run `36280543038` reaches a terminal
state. No runtime change is justified from this partial observation alone.
