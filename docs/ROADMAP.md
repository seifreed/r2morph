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

Status: `completed`

Delivered:

- Keep official support limited to `nop`, `substitute`, and `register`.
- Keep `block`, `dead-code`, `opaque`, `expand`, and `cff` marked as experimental.
- Make the stable subset visible in docs, CLI defaults, and tests.
- Help text and CLI warnings explicitly call out experimental passes.
- CI gates separate stable and experimental test runs.
- Package metadata reflects stable mutation focus.

### Phase 8: Product Corpus and Acceptance Tests

Status: `completed`

Delivered:

- Maintain a small, deterministic ELF x86_64 corpus.
- Add product acceptance coverage for each stable pass.
- Add rollback and invalid-mutation regression coverage.
- Expand the product-smoke suite with per-pass fixtures.
- Split tests more clearly into `unit`, `integration`, `product_smoke`, and `slow`.

### Phase 9: Product UX

Status: `completed`

Delivered:

- Present the engine as `mutate`, `validate`, and `report`.
- Expose product-centric flags for validation mode, rollback policy, seed, and output report.
- CLI help text documents stable vs experimental mutations.
- JSON report contains all relevant mutation, validation, and summary fields.

### Phase 10: Experimental Symbolic Validation

Status: `completed`

Delivered:

- Add an experimental symbolic validator for a narrow subset of cases.
- `symbolic` is exposed as an experimental validation mode.
- Reports identify symbolic coverage scope, backend availability, bounded-step results, and fallback reasons.
- `InstructionSubstitution` tags bounded-step results that map to known equivalence groups.
- Structural validation remains the blocking fallback.

Scope limits:

- `ELF x86_64` only.
- One simple pass at a time.
- Small functions or tightly bounded regions only.

Success criteria:

- The CLI exposes `symbolic` as experimental without implying general semantic equivalence.
- The report identifies when symbolic validation ran, what region it covered, whether a bounded step executed, and why it passed or failed.

## All Phases Complete

The core product roadmap has been fully implemented:

1. **Phase 1-6**: Foundation complete (mutation tracking, pipeline, validation, reporting)
2. **Phase 7**: Stable subset clearly defined (`nop`, `substitute`, `register`) with experimental areas marked
3. **Phase 8**: Product acceptance tests in place with per-pass fixtures
4. **Phase 9**: CLI UX polished (`mutate`, `validate`, `report` commands)
5. **Phase 10**: Experimental symbolic validation available

## Future Direction

### Near-Term Improvements

1. **Expand Architecture Support**
   - Add `arm64` to stable architecture support
   - Improve `PE` and `Mach-O` format handling

2. **Enhance Symbolic Validation**
   - Expand bounded-step coverage for more instruction patterns
   - Improve observable comparison accuracy

3. **Performance Optimization**
   - Reduce memory footprint for large binaries
   - Parallelize mutation pass execution

4. **Documentation**
   - Add more examples for common workflows
   - Document report JSON schema formally

### Experimental Features (Secondary)

These remain experimental and not part of the stable core:

- `expand` mutation pass (instruction expansion)
- `block` mutation pass (block reordering)
- `opaque` mutation pass (opaque predicates)
- `dead-code` mutation pass (dead code injection)
- `cff` mutation pass (control flow flattening)
- Devirtualization analysis
- Enhanced anti-analysis detection
- Instrumentation frameworks

### Version Roadmap

- **0.2.x**: Stability improvements, bug fixes, documentation
- **0.3.0**: Additional stable mutation patterns, architecture expansion
- **0.4.0**: Performance optimizations, extended corpus support
