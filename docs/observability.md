# Logging and observability

r2morph is a local, one-shot binary analysis and mutation CLI. Its
observability design therefore favors safe structured logs and bounded local
files over a mandatory remote collector.

## Architecture

Application modules use the Python standard library and create a module logger:

```python
import logging

logger = logging.getLogger(__name__)
```

`r2morph.utils.logging.setup_logging` owns process-boundary configuration.
Business and domain modules do not select handlers or formats. The configured
`r2morph` parent logger supplies:

- human-readable stderr output for development;
- newline-delimited JSON for production;
- optional size-based rotating files;
- secret, host-path, control-character, and payload-size sanitization;
- operation and correlation context based on `contextvars`;
- UTC timestamps and normalized event fields;
- controlled handler closure at reconfiguration and process shutdown.

The mutation pipeline keeps its event construction in
`r2morph.pipeline.observability`, separate from mutation policy.

Enhanced analysis emits a correlated start and completion event for each
`analyze` operation. Recoverable phase failures and unavailable optional phases
emit warning events while retaining the existing terminal guidance.

CLI analysis, function listing, diff, validation, report, and cache operations
emit correlated lifecycle events. Validation also records its pass/fail result
separately from whether the validator itself ran successfully.

## Configuration

Explicit `setup_logging` arguments override environment values for the
legacy `level` and `log_file` entry points. New applications should use
`LoggingConfig` or the environment.

| Variable | Default | Meaning |
|---|---:|---|
| `R2MORPH_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` |
| `R2MORPH_LOG_FORMAT` | automatic | `console` or `json` |
| `R2MORPH_ENVIRONMENT` | `development` | Event environment; `production` selects JSON by default |
| `R2MORPH_LOG_FILE` | unset | Optional local rotating log file |
| `R2MORPH_LOG_MAX_BYTES` | `10485760` | Maximum active file size |
| `R2MORPH_LOG_BACKUP_COUNT` | `5` | Number of rotated files retained |

Example:

```bash
R2MORPH_ENVIRONMENT=production \
R2MORPH_LOG_LEVEL=INFO \
R2MORPH_LOG_FILE=./r2morph.jsonl \
r2morph mutate sample.bin -o sample.mutated
```

Logs use stderr so stdout remains available for command output and JSON report
rendering. If the file destination cannot be opened, r2morph emits a
`logging.destination_unavailable` event to stderr and continues without the
file handler.

## Levels

Use the lowest-volume level that still describes the operational impact:

| Level | Contract |
|---|---|
| `DEBUG` | Per-pass scheduling, parser fallbacks, bounded diagnostic detail |
| `INFO` | Lifecycle completion, state transitions, and successful outcomes |
| `WARNING` | Recoverable degradation, retry, timeout, rollback, or fallback |
| `ERROR` | One operation failed, but the process can report or continue |
| `CRITICAL` | A process-wide invariant prevents controlled continuation |

Python's standard logging API has no `TRACE` level. r2morph deliberately uses
`DEBUG` as its finest level instead of creating a project-specific level.
`CRITICAL` is reserved rather than emitted for ordinary command failures.

## JSON event contract

Every JSON record includes:

- `timestamp`: UTC RFC 3339 timestamp ending in `Z`;
- `level`, `message`, `service`, `component`, and `environment`;
- `process_id` and `thread_name`.

Events add fields only when meaningful:

- `operation`, `event_name`, `correlation_id`, `request_id`;
- `duration_ms`, `status`, and `outcome`;
- `error_type`, `error_code`, and `stack_trace`;
- bounded pass counters and pass identity.

`trace_id` and `span_id` are accepted when a real tracing integration
provides them. r2morph does not invent them.

Example:

```json
{"timestamp":"2026-11-02T06:30:00.000Z","level":"INFO","message":"Mutation pass completed","service":"r2morph","component":"r2morph.pipeline.pipeline","environment":"production","process_id":1234,"thread_name":"MainThread","operation":"pipeline.pass","event_name":"pipeline.pass.completed","correlation_id":"7d5f...","duration_ms":4.281,"status":"applied","outcome":"success","mutation_count":3,"pass_name":"NopInsertion"}
```

## Correlation and concurrency

`logging_context` binds context without mutable globals. Context is restored
on exit, propagates through async tasks, and is copied into parallel stage
threads. `observed_operation` creates a correlation identifier only at an
operation boundary and reuses an existing identifier for nested work.

Nested failures produce an outcome event at each relevant boundary, but only
the first boundary emits the traceback. This preserves the operation hierarchy
without duplicating the same stack.

Standard handlers serialize threads. Handlers inherited by forked process
workers are filtered to the configuring process because rotating files are not
multi-process safe. The parent executor remains responsible for task outcome
events. Spawned workers do not receive process-global logging state.

## Security and data minimization

Formatting applies the same safety policy to console and JSON output:

- password, token, API-key, authorization, cookie, session, and private-key
  patterns are redacted;
- absolute host paths become basename-only placeholders;
- control characters are escaped to prevent forged records;
- messages and tracebacks are capped at 4096 characters;
- bytes become a size and short SHA-256 prefix, never raw content;
- structured collections are capped at 20 items.

Do not pass sample buffers, complete disassembly, subprocess output, environment
maps, or report payloads as log fields. Log counts, hashes, bounded previews,
addresses, and typed outcomes instead. Sanitization is a final guardrail, not a
reason to add sensitive inputs.

SARIF artifact URIs contain only input and output basenames. Reports omit the
host source root so sharing evidence does not disclose the analyst's paths.

## Resilience and retention

The CLI is low-volume and synchronous, so an asynchronous logging queue is not
justified without profiling evidence. Standard handlers provide thread locks,
and formatting is bounded. File rotation defaults to approximately 60 MiB
total retention: one 10 MiB active file and five backups.

The background cache cleaner samples consecutive failures at powers of two and
emits a recovery event, preventing a failing cleanup loop from producing a log
storm. Shutdown waits for the cleaner and reports a stop timeout.

## Metrics and tracing decision

r2morph has no HTTP service, database server, message broker, or distributed
request path. Operation durations, error outcomes, mutation counts, and report
timings provide the useful local signals. A mandatory metrics backend or
distributed tracing SDK would add infrastructure without a diagnostic path it
could connect.

Add tracing only if a future deployment introduces real cross-process or
cross-service propagation. Pass existing W3C trace identifiers through the
normalized `trace_id` and `span_id` fields; do not synthesize them from the
correlation identifier.

## Adding a new event

1. Use `logging.getLogger(__name__)` in the owning module.
2. Emit an outcome at the operation boundary; add a DEBUG start event only when
   it helps diagnose stalls.
3. Use a stable dotted `event_name` and imperative `operation`.
4. Put identifiers and counters in normalized `extra` fields.
5. Use `log_exception_once` when a failure can cross observed layers.
6. Add a real test that parses the event and verifies correlation, safety, and
   bounded content.

For a new top-level operation:

```python
with observed_operation(logger, "analysis.run", event_name="analysis.run"):
    run_analysis()
```

For an outcome with domain fields:

```python
logger.info(
    "Mutation pass completed",
    extra={
        "event_name": "pipeline.pass.completed",
        "operation": "pipeline.pass",
        "outcome": "success",
        "pass_name": mutation_pass.name,
        "mutation_count": mutation_count,
    },
)
```

## Diagnosis

- Set `R2MORPH_LOG_LEVEL=DEBUG` for bounded local diagnostics.
- Set `R2MORPH_LOG_FORMAT=json` to inspect exact fields locally.
- Search by `correlation_id` to reconstruct CLI, engine, pipeline, and external
  process work.
- Search `outcome=failure`, `outcome=partial_failure`, or
  `outcome=rolled_back` before reading stack traces.
- Check `logging.destination_unavailable` if an expected file is absent.

Call `shutdown_logging()` in embedded long-running applications after the
final operation. The CLI registers the same cleanup for normal interpreter
shutdown.
