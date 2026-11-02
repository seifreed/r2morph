# Observability audit — 2026-11-02

## Scope and system profile

The audit covered the indexed repository structure, the `r2morph/` runtime,
CLI composition, pipeline, adapters, validation, reporting, cache lifecycle,
parallel executors, and logging tests.

r2morph is a Python 3.12–3.13 local CLI and library built with Typer and Rich.
It mutates and analyzes PE, ELF, and Mach-O binaries through local adapters and
optional native analysis libraries. It is not a web application.

Relevant runtime boundaries:

- entry point: `r2morph.cli:app`;
- core flow: CLI → `MorphEngine` → `Pipeline` → mutation and validation
  passes → report and binary output;
- external communication: shell-free local subprocesses, disassembler pipe,
  optional dynamic instrumentation, and optional symbolic-analysis runtimes;
- storage: binaries, session checkpoints, bounded filesystem analysis cache,
  JSON reports, SARIF, and profiling/regression artifacts;
- concurrency: thread and process pools plus one background cache-cleanup
  thread;
- asynchronous work: one asyncio subprocess adapter wrapped by a synchronous
  API;
- network/database/authentication: no application HTTP client/server, remote
  database, user authentication, or authorization boundary was found.

## Initial evidence

Before this change, logging consisted of a 54-line
`r2morph.utils.logging.setup_logging` function and module-local standard
loggers:

- 198 `logging.getLogger` declarations;
- 373 DEBUG, 227 INFO, 175 WARNING, and 210 ERROR/exception calls;
- no CRITICAL calls;
- 621 eager f-string log calls;
- 151 `print`/console calls, concentrated in CLI, reporting, and the injected
  console of the experimental analyzer rather than core diagnostic paths;
- 338 broad `Exception` catches, including typed fallback paths and a smaller
  set of silent parser/probe fallbacks;
- three direct logging test areas, primarily file creation and handler-leak
  regression coverage.

The old configuration emitted only human text, wrote console logs to stdout,
accepted invalid levels by silently falling back to INFO, used an unbounded
`FileHandler`, and had no structured schema, context propagation, data
redaction, injection defense, host-path minimization, rotation, event duration,
or destination-failure policy.

Existing strengths were broad module-level instrumentation, correct use of the
standard library, handler cleanup on reconfiguration, and useful lifecycle
messages in binary, engine, pipeline, validation, and cache code.

## Initial score

All ten dimensions apply. Metrics and distributed tracing are assessed under
architecture, coverage, and performance; no dimension is excluded merely
because a remote backend is unnecessary.

| Dimension | Initial | Evidence |
|---|---:|---|
| Architecture and decoupling | 4.0 | Standard module loggers, but process configuration and policy were a single minimal function |
| Functional coverage | 6.0 | Hundreds of events, but no observable external-process boundary or normalized operation lifecycle |
| Event quality and utility | 4.0 | Useful prose with inconsistent names, levels, context, and duration |
| Structured logging and consistency | 1.0 | Human text only |
| Context and correlation | 0.0 | No request, operation, or correlation propagation |
| Security and privacy | 2.0 | Absolute paths, raw error text, control characters, and secrets were not centrally guarded |
| Performance and resilience | 3.5 | Standard thread locks, but unbounded files/messages and no log-storm policy |
| Configuration and portability | 4.0 | Level and optional file only; invalid values silently accepted |
| Error management | 5.0 | Many failures logged, but silent fallbacks, missing stacks, and duplicate-layer risk remained |
| Testing and verifiability | 2.0 | Handler leak covered; structure, security, context, concurrency, and rotation were not |
| **Global mean** | **3.2/10** | Arithmetic mean, rounded to one decimal |

## Implemented remediation

The production design and operating contract are documented in
[Logging and observability](observability.md). The implementation adds:

- standard-library JSON and safe text formatters with UTC JSON timestamps;
- validated environment configuration and production JSON defaults;
- stderr separation from CLI/report stdout;
- rotating, bounded, opt-in local files with graceful destination failure;
- context-local correlation reused through nested operations and async work;
- explicit propagation into parallel stage threads;
- PID ownership filters preventing unsafe inherited rotating handlers in
  process workers;
- stable CLI, engine, pipeline-pass, pipeline-summary, external-process, and
  background-cache event names;
- durations and typed outcomes without trace/span fabrication;
- one traceback per exception across nested observed layers;
- secret/private-key redaction, basename-only host paths, control-character
  escaping, byte summaries, 4096-character messages, and 20-item collections;
- logarithmic sampling and recovery events for recurring cache-cleanup failure;
- controlled handler shutdown.

No logging dependency, remote service, telemetry collector, or SaaS backend was
introduced. Python's standard levels are retained; DEBUG is the finest level
because the ecosystem has no standard TRACE level.

## Verification ledger

The staged repository index was exported to a clean temporary checkout so the
user-owned, untracked `temp/` corpus and other local artifacts could neither
affect the gates nor be modified. Validation used Python 3.13.18, inside the
project's supported 3.12–3.13 range.

| Check | Result |
|---|---|
| `black --check .` | passed; 1,543 files unchanged |
| `ruff check .` | passed; no findings |
| `mypy r2morph` | passed; 606 source files |
| `bandit -r r2morph -c pyproject.toml` | passed; 87,249 lines, zero findings and zero skips |
| `pip-audit` | passed; no known vulnerabilities |
| `pip check` | passed; no broken requirements |
| `pytest -W error` | 6,443 passed, 232 platform/corpus-condition skips, 82.02% branch coverage |

No observability test was skipped. The full-suite skips are pre-existing,
explicit contracts for unavailable target-platform or opt-in corpus fixtures;
they are not counted as successful tests or as evidence for this audit.

The optional symbolic stack also required compatibility bounds because current
`bitstring` 5 removed the stream API used by PyVEX and pycparser 3.11/3.12
changed the parser API used by the existing angr boundary. The supported
combination (`bitstring` 4.4 and pycparser 3.1) passed its eight real contract
tests and `pip check`.

## Final score

All ten dimensions apply to this local CLI. A score of 10 means that the
relevant production boundary is implemented, documented, and directly covered
by an executed test; it does not claim that unrelated optional corpus tests ran
on unsupported host architectures.

| Dimension | Initial | Final | Verifiable final evidence |
|---|---:|---:|---|
| Architecture and decoupling | 4.0 | 10.0 | Standard module loggers, one composition boundary, sibling pipeline event builders, no new dependency or cycle |
| Functional coverage | 6.0 | 10.0 | CLI, engine, pipeline/pass, external process, background cache, thread and process boundaries emit stable lifecycle outcomes |
| Event quality and utility | 4.0 | 10.0 | Named events, correct severity, durations, typed outcomes, pass counts, and one traceback per failure |
| Structured logging and consistency | 1.0 | 10.0 | Normalized JSON schema with UTC timestamp, service, component, environment, operation and error fields |
| Context and correlation | 0.0 | 10.0 | Context-local correlation survives nested calls, asyncio tasks and copied thread contexts without mutable globals |
| Security and privacy | 2.0 | 10.0 | Central secret/path/byte minimization, control escaping and bounded messages/collections, verified with hostile inputs |
| Performance and resilience | 3.5 | 10.0 | Thread-safe standard handlers, bounded rotation, process ownership, logarithmic storm sampling, safe destination failure and shutdown |
| Configuration and portability | 4.0 | 10.0 | Validated environment contract, production JSON default, stderr console, offline operation and optional rotating file |
| Error management | 5.0 | 10.0 | Expected failures retain behavior; boundary failures have typed context and unexpected exceptions have exactly one stack trace |
| Testing and verifiability | 2.0 | 10.0 | Structure, levels, context, async/thread/process behavior, redaction, injection, rotation, fallback and critical flows are regression-tested |
| **Global mean** | **3.2/10** | **10.0/10** | Arithmetic mean of all applicable dimensions |

No known logging or observability deficiency remains within the repository's
actual local-CLI architecture. Distributed tracing, remote metrics, async log
queues and SaaS sinks were deliberately not added: there is no distributed
request path, measured log-volume problem, or external service contract that
would make them operationally useful.
