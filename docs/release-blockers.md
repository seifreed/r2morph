# Release Blockers

This ledger records the remaining blockers from the current release-hardening
review. It is not a feature roadmap and must not be read as a support claim.

## Open blockers

- RB-001: Per-pass maturity remains incomplete: native evidence, performance,
  composition, false-positive measurement, analyzer effectiveness, and
  affected-instruction coverage are not complete for every pass. Evidence map:
  [pass-maturity.md](pass-maturity.md),
  [support-matrix.json](support-matrix.json) `maturity_evidence_blockers`
  and `maturity_blocker_totals`.
  Exit criteria: every pass has
  complete native, performance, composition, false-positive, analyzer, and
  affected-instruction evidence.
- RB-002: Differential corpus coverage remains incomplete beyond the scheduled all-pass
  Linux ELF x86-64 campaign. PE/Mach-O, ARM32, x86 32-bit, and AArch64 have
  execution smoke cases for the core passes (AArch64 now includes a fifth
  constant-unfolding case), but still require
  broader platform coverage and per-pass evidence. Evidence map:
  [compatibility-corpus.md](compatibility-corpus.md),
  [differential-corpus.yml](../.github/workflows/differential-corpus.yml)
  `continuous_evidence_blockers`, `continuous_evidence_blocker_totals`,
  `extended_maturity_evidence_blockers`, and
  `extended_maturity_evidence_blocker_totals`.
  Exit criteria: all relevant passes have complete differential evidence across
  the supported corpus and declared platform matrix.
- RB-003: VM semantics remain incomplete for memory, calls, ABI, unwinding, TLS/signals,
  threads, FP/SIMD, and SSA/liveness. The complete 151-fixture native parity campaign
  now runs continuously across three deterministic seeds (453 fixture runs), including
  ordinary unwind metadata and non-linear CFG liveness fixtures. LSDA/landing-pad
  exception transformation remains fail-closed and is covered by a separate regression
  contract; it is not claimed as full language-level exception virtualization. Unsupported instructions must still fail closed with
  precise diagnostics. Evidence map:
  [compatibility-corpus.md](compatibility-corpus.md),
  [support-matrix.json](support-matrix.json) `vm_semantic_gap_scope`
  and `vm_semantic_blocker_totals`,
  [independent-review-packet.md](independent-review-packet.md). Exit criteria:
  every unsupported instruction reports the precise rejected instruction and
  missing capability, and supported VM semantics cover the declared ISA scope.
- RB-004: PE, Mach-O, ARM, and AArch64 remain preview or experimental and do not have
  parity with Linux ELF x86-64. Evidence map:
  [support-matrix.json](support-matrix.json) `parity_evidence_blockers`
  and `parity_blocker_totals`,
  [pass-maturity.md](pass-maturity.md). Exit criteria: preview targets either
  reach equivalent evidence to Linux ELF x86-64 or remain explicitly
  non-official in the support matrix.
- RB-005: The adversarial benchmark still needs comparable continuous campaigns across
  analyzers. Binary Ninja is an explicit slot, but unavailable environments are
  non-passing evidence rather than completion. Evidence map:
  [compatibility-corpus.md](compatibility-corpus.md),
  [adversarial-benchmark.yml](../.github/workflows/adversarial-benchmark.yml)
  `adversarial_evidence_blockers` and `adversarial_evidence_blocker_totals`.
  Exit criteria: every analyzer slot has completed comparable scheduled
  campaign rows, including Binary Ninja; unavailable rows remain blockers with
  reasons until completed. The campaign is partitioned into four deterministic
  fixture shards and merged before the corpus-wide gate runs; this addresses
  campaign sustainability but does not close the Binary Ninja availability
  blocker.
- RB-006: VM resistance still needs adversarial validation for ISA/opcode diversity,
  dispatchers, handlers, anti-tamper and progressive bytecode protection.
  Evidence map: [protection-handler-clustering.json](protection-handler-clustering.json),
  [protection-bytecode-grammar.json](protection-bytecode-grammar.json)
  `adversarial_validation` and `vm_resistance_blocker_totals`, plus the automated
  tamper/progressive smoke in
  [adversarial-benchmark.yml](../.github/workflows/adversarial-benchmark.yml).
  Exit criteria: adversarial review validates VM diversity, anti-tamper, and
  progressive bytecode protection instead of treating seed diversity or the
  automated smoke as signoff.
- RB-007: The VM milestone remains blocked until external human review records signoff.
  Evidence map: [independent-review.json](independent-review.json)
  `human_signoff` and `release_decision`,
  [independent-review-packet.md](independent-review-packet.md). Exit criteria:
  external human review records signoff for the VM milestone and the release
  decision no longer blocks the VM milestone.

## Blocker index

| ID | Area | Evidence |
|---|---|---|
| RB-001 | per-pass maturity | `support-matrix.json` `pass-maturity.md` |
| RB-002 | differential evidence | `compatibility-corpus.md` `differential-corpus.yml` |
| RB-003 | VM semantics | `support-matrix.json` `independent-review-packet.md` |
| RB-004 | cross-platform parity | `support-matrix.json` `pass-maturity.md` |
| RB-005 | adversarial benchmark | `compatibility-corpus.md` `adversarial-benchmark.yml` |
| RB-006 | VM resistance | `protection-handler-clustering.json` `protection-bytecode-grammar.json` |
| RB-007 | human VM signoff | `independent-review.json` `independent-review-packet.md` |
