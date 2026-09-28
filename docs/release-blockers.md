# Release Blockers

This ledger records the remaining blockers from the current release-hardening
review. It is not a feature roadmap and must not be read as a support claim.

## Resolved blockers

- RB-001: Per-pass maturity remains incomplete was resolved for the declared
  analyzer/decompiler effectiveness contract. The authoritative scheduled
  adversarial run `36381653200` records `7,964/7,964` expected pass rows and
  `22/22` passes comparable with complete `radare2`, `angr`, and `ghidra`
  evidence. The optional Binary Ninja and IDA slots remain explicit
  unavailable rows rather than being treated as required evidence. Evidence map:
  [pass-maturity.md](pass-maturity.md),
  [support-matrix.json](support-matrix.json) `maturity_evidence_blockers`
  and `maturity_blocker_totals`.
  Exit criteria: every declared pass has complete comparable evidence from the
  required three analyzers and the generated maturity summary reports zero
  decompiler effectiveness blockers.

- RB-002: The declared differential preview matrix is complete. Run
  [`36378342000`](https://github.com/seifreed/r2morph/actions/runs/36378342000)
  completed the aggregate with `5/5` platform reports, zero failures, zero
  errors, and no missing required cases for PE, Mach-O ARM64, ARM32, AArch64,
  and x86-32. The historical entry “Differential corpus coverage remains
  incomplete” is closed for this declared matrix. The bounded matrix remains
  preview evidence and does not promote those targets to parity with official
  Linux ELF x86-64; the contractual parity gap remains open. Evidence map:
  [compatibility-corpus.md](compatibility-corpus.md),
  [differential-corpus.yml](../.github/workflows/differential-corpus.yml)
  `continuous_evidence_blockers`, `continuous_evidence_blocker_totals`,
  `extended_maturity_evidence_blockers`, and
  `extended_maturity_evidence_blocker_totals`. Exit criteria: the declared
  preview platform aggregate remains complete and any new missing or failed
  platform report reopens this blocker.

- RB-003: VM semantic coverage is complete for the declared ELF x86-64 scope:
  memory, direct and indirect calls, ABI/varargs, ordinary unwinding, TLS/signals,
  threads, FP/SIMD, SSA/liveness, and the declared LSDA/landing-pad C++ corpus
  all pass their campaigns. The LSDA gate now covers seven real regression cases
  plus sixteen GCC/Clang generated profiles, with zero runtime or semantic
  failures. Unsupported language or ABI combinations remain fail-closed and are
  not silently treated as unrestricted exception virtualization. Evidence map:
  [support-matrix.json](support-matrix.json) `vm_semantic_resolved_evidence`,
  `vm_semantic_gap_scope` (empty),
  and `vm_semantic_blocker_totals`,
  [protection-vm-semantic-2026-09-18-1d0b69e4.json](protection-vm-semantic-2026-09-18-1d0b69e4.json),
  [protection-lsda-generated-cpp-2026-09-23-705bd5d0.json](protection-lsda-generated-cpp-2026-09-23-705bd5d0.json),
  [independent-review-packet.md](independent-review-packet.md). Exit criteria:
  every declared capability remains covered by a passing campaign and unsupported
  instructions continue to fail closed with precise diagnostics.

## Mixed-status blockers

- RB-004: PE, Mach-O, ARM, and AArch64 remain preview or experimental and do not have
  parity with Linux ELF x86-64. Evidence map:
  [support-matrix.json](support-matrix.json) `parity_evidence_blockers`,
  `parity_blocker_totals`, and the native per-platform aggregation in
  `scripts/platform_evidence.py`,
  [pass-maturity.md](pass-maturity.md). Exit criteria: preview targets either
  reach equivalent evidence to Linux ELF x86-64 or remain explicitly
  non-official in the support matrix.
- RB-005: The adversarial benchmark's required cross-tool campaign is resolved.
  Run `36381653200` contains complete comparable `radare2`, `angr`, and `ghidra`
  rows for all 22 declared passes. Binary Ninja is deliberately on hold for
  this milestone: it remains an explicit unavailable slot and is not silently
  omitted, but no installation work is planned in the current campaign.
  Evidence map:
  [compatibility-corpus.md](compatibility-corpus.md),
  [adversarial-benchmark.yml](../.github/workflows/adversarial-benchmark.yml)
  `adversarial_evidence_blockers` and `adversarial_evidence_blocker_totals`.
  Exit criteria: the required three-tool comparable campaign remains complete;
  Binary Ninja remains a recorded unavailable hold with its reason. The
  campaign is partitioned into deterministic fixture shards and merged before
  the corpus-wide gate runs; this addresses campaign sustainability.
- RB-006: The automated VM-resistance campaign is complete for fifteen fixtures
  across ten seeds: semantic parity, opcode/handler/dispatcher diversity,
  anti-tamper and progressive bytecode protection, plus bounded recovery
  probes all passed. The remaining blocker is external human adversarial review;
  automated evidence does not constitute human signoff.
  Evidence map: [protection-vm-resistance-2026-09-22-e3a491b3.json](protection-vm-resistance-2026-09-22-e3a491b3.json),
  [protection-vm-resistance-2026-09-20.json](protection-vm-resistance-2026-09-20.json),
  [protection-handler-clustering.json](protection-handler-clustering.json),
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

The continuous fuzzing scope has an additional reproducible local run at
[protection-fuzz-2026-09-22-d02bc5b2.json](protection-fuzz-2026-09-22-d02bc5b2.json):
20,000 target runs across 5,000 deterministic cases completed with zero
failures. This strengthens the fuzzing evidence but does not close the
remaining resistance and signoff blockers without adversarial and human review.
The current scheduled workflow also passed 20,000 target runs on commit
`0933d50c`; its retained summary is
[protection-fuzz-2026-09-23-0933d50c.json](protection-fuzz-2026-09-23-0933d50c.json).

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
