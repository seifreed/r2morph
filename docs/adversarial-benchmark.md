# Adversarial benchmark

The CLI entry point is `scripts/adversarial_benchmark.py`. It re-exports the
existing helper names used by the release checks and delegates work to these
focused modules:

| Module | Responsibility |
| --- | --- |
| `adversarial_benchmark_tools.py` | Analyzer adapters and analyzer-specific timeouts. |
| `adversarial_benchmark_passes.py` | Normalize mutation results for reports. |
| `adversarial_benchmark_metrics.py` | Aggregate tool and decompiler measurements. |
| `adversarial_benchmark_campaign.py` | Campaign totals and release blockers. |
| `adversarial_benchmark_execution.py` | Run and account for each mutation pass. |
| `adversarial_benchmark_worker.py` | Analyze and mutate one staged binary in a child process. |

Each analysis-plus-pass worker has a 180 second limit. The process adapter
terminates the worker and its child processes on timeout. The worker records
whether it timed out during binary analysis or during the pass. If analysis
times out, remaining passes for that binary are marked as errors without
repeating the same analysis. A timeout during a pass marks that pass as an
error and allows later passes to continue.

Every failed pass retains a row for each expected analyzer, including the
custom measurement slot. These rows remain errors in campaign summaries; they
preserve evidence shape but do not count as completed analyzer results or
release approval.

The sharded workflow invokes the same CLI contract:

```bash
python scripts/adversarial_benchmark.py \
  --all \
  --dataset fixtures/dataset \
  --generated-corpus \
  --passes all \
  --require-applied \
  --require-tool-slots \
  --fixture-shard-index 0 \
  --fixture-shard-count 32 \
  --output adversarial-benchmark.json
```
