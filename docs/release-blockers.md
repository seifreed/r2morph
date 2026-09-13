# Release Blockers

This ledger records the remaining blockers from the current release-hardening
review. It is not a feature roadmap and must not be read as a support claim.

## Open blockers

- Per-pass maturity remains incomplete: native evidence, performance,
  composition, false-positive measurement, analyzer effectiveness, and
  affected-instruction coverage are not complete for every pass.
- Differential corpus coverage remains incomplete beyond the scheduled all-pass
  Linux ELF x86-64 campaign; more corpus families, generated inputs, and
  platform coverage are still required.
- VM semantics remain incomplete for memory, calls, ABI, unwinding, TLS/signals,
  threads, FP/SIMD, and SSA/liveness. Unsupported instructions must fail closed
  with precise diagnostics.
- PE, Mach-O, ARM, and AArch64 remain preview or experimental and do not have
  parity with Linux ELF x86-64.
- The adversarial benchmark still needs comparable continuous campaigns across
  analyzers. Binary Ninja is an explicit slot, but unavailable environments are
  non-passing evidence rather than completion.
- VM resistance still needs adversarial validation for ISA/opcode diversity,
  dispatchers, handlers, anti-tamper and progressive bytecode protection.
- The VM milestone remains blocked until external human review records signoff.
