# Release Blockers

This ledger records the remaining blockers from the current release-hardening
review. It is not a feature roadmap and must not be read as a support claim.
The machine-readable [1.0 readiness ledger](one-zero-readiness.json) records
the evidence requirements and keeps stable-major releases blocked while any
criterion remains open or in progress.

## Latest full CI verification of a code-bearing commit

Commit `0134656bc95668af4ca5a40af07cb6e9166bd4dc` passed CI run
[`43008805011`](https://github.com/seifreed/r2morph/actions/runs/43008805011)
with all 15 jobs successful. The run includes unit and integration suites,
installed-wheel smoke tests, property and fuzz validation, lint and type
checking, and macOS, Windows, and Ubuntu jobs on Python 3.12 and 3.13. This
result verifies that code commit only; later code changes require their own
successful run.

## Resolved blockers

- The 1.0 compatibility contract is explicit across all 264 pass/format/
  architecture cells. Each cell records declared support, observed status, and
  evidence; unsupported cells cannot carry evidence, and generated-matrix
  freshness is checked in CI. Only Linux ELF x86-64 is official. The other
  formats and architectures remain preview or experimental, so this closes the
  contract requirement without closing the separate parity criterion. Evidence:
  [support-matrix.json](support-matrix.json),
  [compatibility-corpus.md](compatibility-corpus.md), and
  [test_support_matrix_contract.py](../tests/unit/test_support_matrix_contract.py).
- The 1.0 published correctness and observed-cost criteria now cover all 22
  declared passes on official Linux ELF x86-64. Core and extended reports from
  workflow `42980449435` at `019a0551` record complete evidence, zero errors,
  and zero semantic or runtime-observable failures. The extended report covers
  13,032 seeded runs with 3,374 applied transformations and zero output-size
  delta. Its durations are observed corpus costs, not controlled benchmarks.
  This closes only `published_correctness_results` and `published_cost_results`;
  cross-platform parity and general analyzer resistance remain open. Evidence:
  [protection-differential-2026-11-11-019a0551.json](protection-differential-2026-11-11-019a0551.json),
  [protection-extended-differential-2026-11-11-019a0551.json](protection-extended-differential-2026-11-11-019a0551.json),
  and [one-zero-readiness.json](one-zero-readiness.json).
- RB-001: Per-pass maturity remains incomplete was resolved for the declared
  analyzer/decompiler effectiveness contract. The authoritative scheduled
  adversarial run `36381653200` records `7,964/7,964` expected pass rows and
  `22/22` passes comparable with complete `radare2`, `angr`, and `ghidra`
  evidence. The optional Binary Ninja and IDA slots remain explicit unavailable
  rows in that campaign. A later targeted IDA Pro run covers five
  CodeVirtualization fixture pairs, but does not fill the full pass-by-fixture
  matrix or promote the resistance claim. Evidence map:
  [pass-maturity.md](pass-maturity.md),
  [compatibility-corpus.md](compatibility-corpus.md),
  [protection-ida-targeted-2026-11-11-c70a113b.json](protection-ida-targeted-2026-11-11-c70a113b.json),
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
  A subsequent complete run [`43165336266`](https://github.com/seifreed/r2morph/actions/runs/43165336266)
  completed 85/85 jobs. Its 10-pass core and 12-pass extended differential
  campaigns covered 10,860 and 13,032 classified runs respectively, with
  zero errors or failed seeds. The public corpus completed 360 samples with no
  differential or static-recovery failures; all five preview platform slices
  completed their 73 required cases. The hash-bound archived evidence is
  [protection-differential-run-2026-11-12-43165336266.json](protection-differential-run-2026-11-12-43165336266.json).
  This strengthens correctness and bounded preview evidence; it does not close
  the separate cross-platform parity criterion.

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
- RB-005: The required three-decompiler maturity campaign is complete, while
  the broader all-named-analyzer release gate remains open. Run
  [`42987427831`](https://github.com/seifreed/r2morph/actions/runs/42987427831)
  merged all 16 deterministic shards and recorded comparable
  `radare2`, `angr`, and `ghidra` evidence for all 22 passes. Across 7,964
  pass rows, 2,341 transformations were applied, with zero pass errors or
  missing rows. The campaign observed all 71,676 expected analyzer slots, but
  only 55,220 runs completed (77.04%); 17 evidence blockers remain. Binary
  Ninja's module and IDA Pro's `idat` executable were unavailable, Unicorn had
  528 unsupported-instruction rows, and angr lacked three decompiler baseline
  pairs. Triton completed all 7,964 runs and Unicorn completed 7,436 (93.37%).
  Binary Ninja is deliberately on hold for this campaign because its licensed
  module is not available. These are recorded unavailable results, not analyzer
  evidence.
  The aggregate records the remaining rows in `adversarial_evidence_blockers`
  and `adversarial_evidence_blocker_totals`; those counts are retained in the
  pinned evidence report.
  Evidence map:
  [protection-adversarial-campaign-2026-11-11-4749bca3.json](protection-adversarial-campaign-2026-11-11-4749bca3.json).
  This closes only the required comparable three-decompiler criterion; it does
  not close `all_named_adversarial_analyzers`.
  A supplemental local calibration at commit `0920b7d32e0ad4c3588150baaa54c25c49d4fff4`
  measured all 22 pass names against `elf_vm_arith_x86_64` with IDA Pro 9.5 and
  Ghidra 11.4.2. Two passes applied and 20 were no-ops; both analyzers completed
  all 22 measurements, and Unicorn returned matching exit codes for all 22
  pairs. This is one fixture and does not fill the pass-by-fixture matrix.
  Binary Ninja remained unavailable because its license was unavailable on the
  host. Evidence: [protection-host-analyzer-calibration-2026-11-11-0920b7d3.json](protection-host-analyzer-calibration-2026-11-11-0920b7d3.json).
  A second local run at commit `92265ab8f9d3577a58d9fb69730ab1359feb5552`
  applies `CodeVirtualization` to ten ELF x86-64 fixtures. IDA Pro 9.5 and
  Ghidra 11.4.2 completed all ten original/protected measurements, and Unicorn
  returned matching exit codes for all ten pairs. All ten transformations
  applied without unsupported functions. The report records 60 of 90 analyzer
  runs completed; angr, Binary Ninja, and Triton were unavailable on the host.
  This adds a bounded pass-by-fixture slice; it does not resolve the remaining
  full analyzer matrix or establish general resistance. Evidence:
  [protection-ida-codevirtualization-shard-2026-11-11-92265ab8.json](protection-ida-codevirtualization-shard-2026-11-11-92265ab8.json).
  A host shard at commit `52dfc2eac82584149dcb6e4c83dd08fd03c040a6` reran
  the same ten fixtures through the available local analyzers. IDA Pro 9.5,
  Ghidra 12.2, angr, Unicorn, radare2, objdump, and the custom analyzer
  completed all 70 expected runs with zero tool errors. Binary Ninja was
  unavailable because its license could not be acquired; Triton was unavailable
  on this macOS host. All ten CodeVirtualization transformations applied with
  zero unsupported functions. This fills ten angr slots and independently
  confirms the IDA/Ghidra/Unicorn slice, but does not complete all pass/fixture
  slots. Evidence:
  [protection-host-adversarial-shard-2026-11-11-52dfc2ea.json](protection-host-adversarial-shard-2026-11-11-52dfc2ea.json)
  and [test_published_host_adversarial_shard.py](../tests/unit/test_published_host_adversarial_shard.py).
  A second deterministic shard at `b8d112a750724fb91f1666760937606af88b36b3`
  applied CodeVirtualization to 11 additional fixtures with zero unsupported
  functions or pass errors. IDA Pro 9.5, Ghidra 12.2, angr, Unicorn, radare2,
  objdump, and the custom analyzer completed all 77 available runs; Binary
  Ninja (license unavailable) and Triton (module unavailable) account for the
  remaining 22/99 slots. No analyzer tool errors occurred. This adds 11 fixture
  pairs to the available host evidence but does not close the all-pass analyzer
  matrix or the resistance criterion. Evidence:
  [protection-host-adversarial-shard-2026-11-11-b8d112a7-shard-01.json](protection-host-adversarial-shard-2026-11-11-b8d112a7-shard-01.json)
  and [test_published_host_adversarial_shard.py](../tests/unit/test_published_host_adversarial_shard.py).
  A third deterministic shard at commit `c5b590cc` applied CodeVirtualization
  to ten more ELF x86-64 fixtures without unsupported functions or pass errors.
  IDA Pro 9.5, Ghidra 12.2, angr, radare2, objdump, and the custom analyzer
  completed all ten original/protected measurements. Unicorn completed nine;
  one fixture used an unsupported instruction. The report records 69/90
  analyzer runs completed, zero tool errors, and 21 unavailable slots: ten
  Binary Ninja slots (license unavailable), ten Triton slots (module
  unavailable), and one Unicorn slot. This adds a bounded fixture slice and
  does not close the full pass/fixture matrix or resistance criterion. Evidence:
  [protection-host-adversarial-shard-2026-11-11-c5b590cc-shard-02.json](protection-host-adversarial-shard-2026-11-11-c5b590cc-shard-02.json)
  and [test_published_host_adversarial_shards_early.py](../tests/unit/test_published_host_adversarial_shards_early.py).
  A fourth host shard at commit `0208d79e` applied CodeVirtualization to ten
  additional fixtures with zero unsupported functions or pass errors. IDA Pro
  9.5, Ghidra 11.4.2, angr, radare2, objdump, and the custom analyzer completed
  all 60 runs; Unicorn completed nine of ten. Binary Ninja remained unavailable
  because its license was unavailable, Triton was not installed, and Unicorn
  did not support one fixture instruction. The report records 69/90 runs and
  zero analyzer tool errors. This adds ten fixture pairs but does not complete
  the full pass-by-fixture analyzer matrix or resistance criterion. Evidence:
  [protection-host-adversarial-shard-2026-11-11-0208d79e-shard-03.json](protection-host-adversarial-shard-2026-11-11-0208d79e-shard-03.json)
  and [test_published_host_adversarial_shards_early.py](../tests/unit/test_published_host_adversarial_shards_early.py).
  A fifth deterministic host shard measured ten additional ELF x86-64 fixtures
  at commit `ebe50ae2`. All ten CodeVirtualization passes applied with zero
  unsupported functions or pass errors. IDA Pro 9.5, Ghidra 11.4.2, angr,
  radare2, objdump, and the custom analyzer completed all 60 paired runs;
  Unicorn completed eight of ten because two fixtures use unsupported
  instructions. Binary Ninja's license and the Triton module were unavailable,
  for 68/90 completed analyzer runs and zero tool errors. This adds ten fixture
  pairs but does not close the full pass/fixture matrix or resistance criterion.
  Evidence: [protection-host-adversarial-shard-2026-11-11-ebe50ae2-shard-04.json](protection-host-adversarial-shard-2026-11-11-ebe50ae2-shard-04.json)
  and [test_published_host_adversarial_shards_early.py](../tests/unit/test_published_host_adversarial_shards_early.py).
  A sixth deterministic host shard measured ten additional ELF x86-64 fixtures
  at commit `811ab859`. All ten CodeVirtualization passes applied with zero
  unsupported functions or pass errors. IDA Pro 9.5, Ghidra 11.4.2, angr,
  Unicorn, radare2, objdump, and the custom analyzer completed all 70 expected
  runs with zero tool errors. Binary Ninja's license and the Triton module were
  unavailable, accounting for the remaining 20/90 slots. This adds ten fixture
  pairs but does not close the full pass/fixture matrix or resistance criterion.
  Evidence: [protection-host-adversarial-shard-2026-11-11-811ab859-shard-05.json](protection-host-adversarial-shard-2026-11-11-811ab859-shard-05.json)
  and [test_published_host_adversarial_shards.py](../tests/unit/test_published_host_adversarial_shards.py).
  A seventh deterministic host shard measured ten additional ELF x86-64
  fixtures at commit `50496238`. All ten CodeVirtualization passes applied
  with zero unsupported functions or pass errors. IDA Pro 9.5, Ghidra 11.4.2,
  angr, Unicorn, radare2, objdump, and the custom analyzer completed all 70
  available runs with zero tool errors. Binary Ninja's license and the Triton
  module were unavailable, accounting for 20/90 slots. This adds ten fixture
  pairs but does not complete the full pass/fixture analyzer matrix or
  resistance criterion. Evidence:
  [protection-host-adversarial-shard-2026-11-11-50496238-shard-06.json](protection-host-adversarial-shard-2026-11-11-50496238-shard-06.json)
  and [test_published_host_adversarial_shards.py](../tests/unit/test_published_host_adversarial_shards.py).
  An eighth host shard measured eleven additional ELF x86-64 fixtures at
  commit `95ada1f8`. All eleven CodeVirtualization passes applied with zero
  unsupported functions or pass errors. IDA Pro 9.5, Ghidra 11.4.2, angr,
  Unicorn, radare2, objdump, and the custom analyzer completed all 77 available
  runs with zero reported tool errors. Binary Ninja's license and the Triton
  module were unavailable, accounting for 22/99 slots. This adds eleven fixture
  pairs but does not complete the full pass/fixture analyzer matrix or
  resistance criterion. Evidence:
  [protection-host-adversarial-shard-2026-11-12-95ada1f8-shard-07.json](protection-host-adversarial-shard-2026-11-12-95ada1f8-shard-07.json)
  and [test_published_host_adversarial_shards.py](../tests/unit/test_published_host_adversarial_shards.py).
  A ninth deterministic host shard measured ten additional ELF x86-64 fixtures
  at commit `a508ec2b`. All ten CodeVirtualization passes applied with zero
  unsupported functions or pass errors. IDA Pro 9.5, Ghidra 11.4.2, angr,
  Unicorn, radare2, objdump, and the custom analyzer completed all 70 available
  runs with zero reported tool errors. Binary Ninja's license and the Triton
  module were unavailable, accounting for 20/90 slots. This adds ten fixture
  pairs but does not complete the full pass/fixture analyzer matrix or
  resistance criterion. Evidence:
  [protection-host-adversarial-shard-2026-11-12-a508ec2b-shard-08.json](protection-host-adversarial-shard-2026-11-12-a508ec2b-shard-08.json)
  and [test_published_host_adversarial_shards.py](../tests/unit/test_published_host_adversarial_shards.py).
  A tenth deterministic host shard measured ten additional ELF x86-64 fixtures
  at commit `c30d1337`. All ten CodeVirtualization passes applied with zero
  unsupported functions or pass errors. IDA Pro 9.5, Ghidra 11.4.2, angr,
  Unicorn, radare2, objdump, and the custom analyzer completed all 70 available
  runs with zero reported tool errors. Binary Ninja's license and the Triton
  module were unavailable, accounting for 20/90 slots. This adds ten fixture
  pairs but does not complete the full pass/fixture analyzer matrix or
  resistance criterion. Evidence:
  [protection-host-adversarial-shard-2026-11-12-c30d1337-shard-09.json](protection-host-adversarial-shard-2026-11-12-c30d1337-shard-09.json)
  and [test_published_host_adversarial_shards.py](../tests/unit/test_published_host_adversarial_shards.py).
  An eleventh host shard measured eleven additional ELF x86-64 fixtures at
  commit `74a3e18d`. All eleven CodeVirtualization passes applied with zero
  unsupported functions or pass errors. angr, Unicorn, radare2, objdump, and
  the custom analyzer completed all 55 available runs with zero reported tool
  errors. Binary Ninja, Ghidra, IDA Pro, and Triton were unavailable in this
  local environment, accounting for 44/99 slots; one angr decompiler baseline
  pair was also unavailable. This adds eleven fixture pairs but does not
  complete the full pass/fixture analyzer matrix or resistance criterion.
  Evidence:
  [protection-host-adversarial-shard-2026-11-12-74a3e18d-shard-10.json](protection-host-adversarial-shard-2026-11-12-74a3e18d-shard-10.json)
  and [test_published_host_adversarial_shards.py](../tests/unit/test_published_host_adversarial_shards.py).
  A supplemental IDA Pro service run analyzed the same eleven original and
  protected fixture pairs. It discovered and decompiled all 16 original and 28
  protected functions with zero errors. Decompiler output grew from 1,746
  bytes/93 lines to 8,139 bytes/308 lines. The service did not expose its
  version; this evidence is separate from the command-line campaign, which
  still records the local `idat` executable as unavailable, and does not
  measure runtime equivalence or general resistance. Evidence:
  [protection-ida-host-adversarial-shard-2026-11-12-74a3e18d-shard-10.json](protection-ida-host-adversarial-shard-2026-11-12-74a3e18d-shard-10.json).
  A twelfth host shard at commit `2867d63b` measured all 22 declared passes on
  ten ELF x86-64 fixtures. CodeVirtualization applied to all ten with zero
  unsupported functions or pass errors; 18 pass/fixture cases applied across
  five pass types, while 17 pass names had no applied transformations in this
  shard. IDA Pro 9.5, Ghidra 12.2, angr, Unicorn, radare2, objdump, and the
  custom analyzer completed all 1,540 available runs with zero tool errors.
  Binary Ninja's license and the Triton module were unavailable for 440 slots.
  This is one of sixteen deterministic shards and does not close the complete
  analyzer matrix or establish general resistance. Evidence:
  [protection-host-adversarial-shard-2026-11-12-2867d63b-shard-00.json](protection-host-adversarial-shard-2026-11-12-2867d63b-shard-00.json)
  and [test_published_host_adversarial_shard_zero.py](../tests/unit/test_published_host_adversarial_shard_zero.py).
  A thirteenth host shard at commit `0ab74d02`, run under supported Python
  3.12, measured all 22 declared passes on ten additional ELF x86-64 fixtures.
  CodeVirtualization applied to all ten without unsupported functions or pass
  errors; 19 applications occurred across six pass types, while 16 pass names
  had no application in this shard. IDA Pro 9.5, Ghidra 12.2, angr, Unicorn,
  radare2, objdump, and the custom analyzer completed 1,518 of 1,980 expected
  runs with zero tool errors or missing rows. Binary Ninja's license and the
  Triton module were unavailable for 440 rows; Unicorn could not execute one
  instruction in each of ten fixtures, accounting for 22 more unavailable
  rows. This is shard 11 of 16 and does not close the complete analyzer matrix
  or establish general resistance. Evidence:
  [protection-host-adversarial-shard-2026-11-12-0ab74d02-shard-11.json](protection-host-adversarial-shard-2026-11-12-0ab74d02-shard-11.json)
  and [test_published_host_adversarial_shard_11.py](../tests/unit/test_published_host_adversarial_shard_11.py).
  Exit criteria: complete the declared analyzer slots, resolve the 17 reported
  evidence blockers, and retain comparable results for all 22 passes.

## Resolved review gates

- RB-006: The independent human review approved the VM resistance evidence on
  commit `a111f923df43a66826b71ab70db8a484532fbf3b`. The reviewer inspected
  VM diversification, dispatch and handler alternatives, anti-tamper and
  progressive bytecode protection, fuzz properties, failure handling, and
  bounded reporting. Evidence map:
  [human-review-signoff.json](human-review-signoff.json),
  [independent-review-packet.md](independent-review-packet.md), and
  [independent-review.json](independent-review.json). The
  [protection-handler-clustering.json](protection-handler-clustering.json) and
  [protection-bytecode-grammar.json](protection-bytecode-grammar.json)
  `adversarial_validation` fields retain the automated evidence scope; the
  [support matrix](support-matrix.json) records zero `vm_resistance_blocker_totals`.
  This resolves only the human signoff requirement. It does not establish
  general resistance to professional reverse engineering or close the 1.0
  `published_resistance_results` criterion.
  The newer automated campaign adds 15 fixtures and ten seeds with semantic
  parity, artifact/opcode/handler/dispatcher diversity, tamper-probe divergence,
  and progressive growth on six fixtures. Its report explicitly remains
  `pending-human-adversarial-review`; see
  [protection-adversarial-campaign-2026-11-11-4749bca3.json](protection-adversarial-campaign-2026-11-11-4749bca3.json)
  and the three pinned VM reports it references. It strengthens smoke evidence
  but does not establish general resistance or close that release criterion.
  Exit criteria: the
  approval remains bound to the reviewed commit; implementation changes require
  another independent review.
- RB-007: Independent human review records signoff for the reviewed VM commit and
  the release decision now reports `signoff-recorded`. The
  `human_signoff` and `release_decision` fields record this state. Evidence map:
  [human-review-signoff.json](human-review-signoff.json),
  [independent-review.json](independent-review.json). Exit criteria: preserve
  the review record and require a new review when the reviewed implementation
  changes.
The continuous fuzzing scope has an additional reproducible local run at
[protection-fuzz-2026-09-22-d02bc5b2.json](protection-fuzz-2026-09-22-d02bc5b2.json):
20,000 target runs across 5,000 deterministic cases completed with zero
failures. This strengthens fuzzing evidence alongside the independent review;
it does not establish parity for preview or experimental targets.
The current scheduled workflow also passed 20,000 target runs on commit
`0933d50c`; its retained summary is
[protection-fuzz-2026-09-23-0933d50c.json](protection-fuzz-2026-09-23-0933d50c.json).
The latest wheel-backed rerun at commit `95cff0fb` completed 20,000 cases per
target (180,000 target runs) with seed `20261111` and zero failures. It adds
deterministic mutations of valid ELF headers, PE optional headers, and Mach-O
load commands alongside malformed bytes, assembly, VM dispatch/codegen,
relocations, and rewriting. The 413 recoverable Mach-O warnings are counted in
the report rather than emitted per input. See
[protection-fuzz-format-aware-2026-11-11-95cff0fb.json](protection-fuzz-format-aware-2026-11-11-95cff0fb.json)
and [workflow run 43067351979](https://github.com/seifreed/r2morph/actions/runs/43067351979).
This strengthens format-parser fuzz evidence; semantic equivalence, full
cross-platform fuzzing, and professional adversarial resistance remain separate
requirements.

A local source-tree rerun at `04e2f5b4` completed 20,000 cases per target
(180,000 target runs) with seed `20261112` and zero failures. Its raw output and
hash-bound summary are
[protection-fuzz-2026-11-12-04e2f5b4-output.json](protection-fuzz-2026-11-12-04e2f5b4-output.json)
and
[protection-fuzz-format-aware-2026-11-12-04e2f5b4.json](protection-fuzz-format-aware-2026-11-12-04e2f5b4.json).
This is source-tree evidence; the separate wheel-backed workflow run remains
the package-installation check. The result does not close semantic-equivalence,
cross-platform fuzz, analyzer-resistance, or parity requirements.

The follow-up wheel-backed workflow on `8d6ceb6a` passed the same nine-target
campaign, with 20,000 cases per target and zero failures. The artifact is
downloaded and hash-bound in
[protection-fuzz-wheel-2026-11-12-8d6ceb6a.json](protection-fuzz-wheel-2026-11-12-8d6ceb6a.json)
and
[protection-fuzz-wheel-2026-11-12-8d6ceb6a-output.json](protection-fuzz-wheel-2026-11-12-8d6ceb6a-output.json);
the workflow run is [43132685797](https://github.com/seifreed/r2morph/actions/runs/43132685797).
It confirms the installed package path but does not close the separate
semantic-equivalence, cross-platform fuzz, resistance, or parity criteria.

The latest installed-wheel follow-up ran the same nine-target, 20,000-case
campaign on Ubuntu, macOS ARM64, and Windows: 540,000 target runs total with
zero failures. Each runner reported 428 recoverable Mach-O parser warnings.
The reports are hash-bound in
[protection-fuzz-wheel-platform-2026-11-12-df55c7a6.json](protection-fuzz-wheel-platform-2026-11-12-df55c7a6.json)
with raw reports for each runner. This closes the declared cross-platform
fuzz execution matrix only; semantic parity, analyzer resistance, and
professional adversarial resistance remain separate open criteria.

## Blocker index

The published `v0.4.0-alpha.3` release pipeline completed all five jobs,
including installed-wheel tests, PyPI publication, provenance attestation, and
GitHub release creation. The release contains the wheel, source archive, SBOM,
and SHA-256 checksums. The pinned run record is
[release-pipeline-2026-09-07.json](release-pipeline-2026-09-07.json), with the
[workflow run](https://github.com/seifreed/r2morph/actions/runs/34096579308)
and [published release](https://github.com/seifreed/r2morph/releases/tag/v0.4.0-alpha.3).
This verifies the alpha release path only; `one-zero-readiness.json` continues
to block stable-major publication until every 1.0 evidence criterion is complete.

| ID | Area | Evidence |
|---|---|---|
| RB-001 | per-pass maturity | `support-matrix.json` `pass-maturity.md` |
| RB-002 | differential evidence | `compatibility-corpus.md` `differential-corpus.yml` |
| RB-003 | VM semantics | `support-matrix.json` `independent-review-packet.md` |
| RB-004 | cross-platform parity | `support-matrix.json` `pass-maturity.md` |
| RB-005 | adversarial benchmark | `compatibility-corpus.md` `adversarial-benchmark.yml` |
| RB-006 | VM resistance | `protection-handler-clustering.json` `protection-bytecode-grammar.json` |
| RB-007 | human VM signoff | `independent-review.json` `independent-review-packet.md` |
