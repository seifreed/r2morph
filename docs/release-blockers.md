# Release Blockers

This ledger records the remaining blockers from the current release-hardening
review. It is not a feature roadmap and must not be read as a support claim.

## Open blockers

- RB-001: Per-pass maturity remains incomplete: native evidence, performance,
  composition, false-positive measurement, analyzer effectiveness, and
  affected-instruction coverage are not complete for every pass. Evidence map:
  [pass-maturity.md](pass-maturity.md),
  [support-matrix.json](support-matrix.json).
- RB-002: Differential corpus coverage remains incomplete beyond the scheduled all-pass
  Linux ELF x86-64 campaign; more corpus families, generated inputs, and
  platform coverage are still required. Evidence map:
  [compatibility-corpus.md](compatibility-corpus.md),
  [differential-corpus.yml](../.github/workflows/differential-corpus.yml).
- RB-003: VM semantics remain incomplete for memory, calls, ABI, unwinding, TLS/signals,
  threads, FP/SIMD, and SSA/liveness. Unsupported instructions must fail closed
  with precise diagnostics. Evidence map:
  [compatibility-corpus.md](compatibility-corpus.md),
  [independent-review-packet.md](independent-review-packet.md).
- RB-004: PE, Mach-O, ARM, and AArch64 remain preview or experimental and do not have
  parity with Linux ELF x86-64. Evidence map:
  [support-matrix.json](support-matrix.json),
  [pass-maturity.md](pass-maturity.md).
- RB-005: The adversarial benchmark still needs comparable continuous campaigns across
  analyzers. Binary Ninja is an explicit slot, but unavailable environments are
  non-passing evidence rather than completion. Evidence map:
  [compatibility-corpus.md](compatibility-corpus.md),
  [adversarial-benchmark.yml](../.github/workflows/adversarial-benchmark.yml).
- RB-006: VM resistance still needs adversarial validation for ISA/opcode diversity,
  dispatchers, handlers, anti-tamper and progressive bytecode protection.
  Evidence map: [protection-handler-clustering.json](protection-handler-clustering.json),
  [protection-bytecode-grammar.json](protection-bytecode-grammar.json).
- RB-007: The VM milestone remains blocked until external human review records signoff.
  Evidence map: [independent-review.json](independent-review.json),
  [independent-review-packet.md](independent-review-packet.md).
