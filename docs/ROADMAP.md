# Product Roadmap

`r2morph` is being developed as a `metamorphic mutation engine with validation`.

The primary product flow is:

`load binary -> apply tracked mutations -> validate -> export mutated binary + report`

Everything outside that path is secondary and currently treated as experimental.

## Current State

The repository now has the foundations of the mutation engine product:

- Product messaging is centered on mutation + validation.
- The stable core is explicitly limited to `ELF`, `x86_64`, and the `nop`, `substitute`, and `register` mutation passes.
- Mutations can be recorded with structured metadata.
- The pipeline supports pass checkpoints, rollback, structural validation, optional runtime validation, and JSON reporting.
- Product-smoke tests cover the current stable flow.

This means the project is no longer positioned as two equal products. The mutation engine is the main line; advanced analysis remains secondary.

## Phase Status

### Phase 1: Re-focus the Project

Status: `completed`

Delivered:

- README and CLI centered on mutation + validation.
- Experimental areas clearly marked as secondary.
- A support matrix published in the main documentation.
- Version and maturity messaging aligned around `0.2.0`.

### Phase 2: Traceable Mutation Model

Status: `completed`

Delivered:

- Structured `MutationRecord` tracking.
- Mutation passes emit concrete mutation records instead of only counters.
- The pipeline accumulates mutation history.

### Phase 3: Pipeline with Checkpoints and Rollback

Status: `completed`

Delivered:

- Checkpoints before each pass.
- Rollback on validation failure.
- Configurable rollback policy for pass-level control.

Notes:

- Pass-level rollback is the current supported path.
- Per-mutation rollback remains partial and should be treated as best effort.

### Phase 4: Integrated Structural Validation

Status: `completed`

Delivered:

- Structural validation manager integrated into the pipeline.
- Invariant baseline/compare flow.
- Patch readback and basic structural sanity checks.

### Phase 5: Runtime Validation

Status: `completed`

Delivered:

- Configurable runtime comparison.
- Multiple test cases via a runtime corpus.
- Comparison controls for exit code, stdout, stderr, and selected files.

Notes:

- This is sample-based equivalence, not a semantic guarantee.

### Phase 6: Formal Engine Reporting

Status: `completed`

Delivered:

- Stable JSON report sections for input, output, passes, mutations, validation, summary, and support matrix.
- CLI commands oriented around report generation and inspection.

### Phase 7: Shrink the Official Core to a Stable Subset

Status: `in progress`

Target:

- Keep official support limited to `nop`, `substitute`, and `register`.
- Keep `block`, `dead-code`, `opaque`, `expand`, and `cff` marked as experimental.
- Make the stable subset visible in docs, CLI defaults, and tests.

Remaining work:

- Tighten help text and package metadata around the stable subset.
- Add CI gates that treat stable and experimental coverage separately.

### Phase 8: Product Corpus and Acceptance Tests

Status: `in progress`

Target:

- Maintain a small, deterministic ELF x86_64 corpus.
- Add product acceptance coverage for each stable pass.
- Add rollback and invalid-mutation regression coverage.

Remaining work:

- Expand the product-smoke suite with per-pass fixtures.
- Split tests more clearly into `unit`, `integration`, `product_smoke`, and `slow`.

### Phase 9: Product UX

Status: `in progress`

Target:

- Present the engine as `mutate`, `validate`, and `report`.
- Expose product-centric flags for validation mode, rollback policy, seed, and output report.

### Phase 10: Experimental Symbolic Validation

Status: `in progress`

Target:

- Add an experimental symbolic validator for a narrow subset of cases.

Current state:

- `symbolic` is exposed as an experimental validation mode.
- Reports now identify symbolic coverage scope, backend availability, bounded-step results, and fallback reasons.
- `InstructionSubstitution` can now tag bounded-step results that also map to a known equivalence group and, when possible, compare a small set of observable register/flag effects on original vs mutated snippets.
- Structural validation remains the blocking fallback; symbolic mode does not claim general semantic equivalence.

Scope limits:

- `ELF x86_64` only.
- One simple pass at a time.
- Small functions or tightly bounded regions only.

Success criteria:

- The CLI can expose `symbolic` as experimental without implying general semantic equivalence.
- The report identifies when symbolic validation ran, what region it covered, whether a bounded step executed, and why it passed or failed.

## Next Execution Block

The next recommended implementation block is:

1. Finish Phase 7 by warning on experimental passes and making the stable subset the only default set.
2. Finish Phase 8 by expanding product-smoke fixtures and adding explicit rollback-failure fixtures.
3. Finish Phase 9 by wiring `--seed` and improving CLI summaries for rollback and validation outcomes.

This keeps the project deep on the product path before adding any new advanced analysis features.
