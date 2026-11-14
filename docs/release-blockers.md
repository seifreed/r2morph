# Release Blockers

This ledger records the remaining blockers from the current release-hardening
review. It is not a feature roadmap and must not be read as a support claim.
The machine-readable [1.0 readiness ledger](one-zero-readiness.json) records
the evidence requirements and keeps stable-major releases blocked while any
criterion remains open or in progress.

## Latest full CI verification on main

Commit `e843192a45026f764c9a65e4403e6a5e28bc1037` passed CI run
[`43549915916`](https://github.com/seifreed/r2morph/actions/runs/43549915916)
with all 15 jobs successful and none skipped. The run includes unit and
integration suites, installed-wheel and product smoke tests, property and fuzz
validation, lint and type checking, and Linux, macOS, and Windows jobs on
Python 3.12 and 3.13. The subsequent release-signoff change at `576f705c` also
passed its full local suite (6,770 passed, 225 skipped); its GitHub CI run
`43558227580` is still queued as of this update. Neither run closes the separate
open 1.0 parity, analyzer-coverage, or resistance criteria below.

The seven-module native macOS ARM64 platform preview was also built from
`60dfc8da`, installed from its wheel, and executed locally on macOS 27.2 with
Python 3.12.16 and radare2 6.2.6. All 35 cases passed with zero failures,
errors, or skips; the JUnit report and wheel SHA-256 are retained in
[protection-platform-macos-arm64-2026-11-14-60dfc8d.json](protection-platform-macos-arm64-2026-11-14-60dfc8d.json)
and
[protection-platform-macos-arm64-2026-11-14-60dfc8d.xml](protection-platform-macos-arm64-2026-11-14-60dfc8d.xml).
This is bounded preview evidence and leaves cross-platform parity open.

On the current source commit `84e1202f`, a fresh wheel-backed fuzz campaign
passed locally on macOS 27.2 ARM64 with Python 3.12.16: 5,000 cases for each of
10 targets (50,000 target runs), zero failures, and 103 counted recoverable
Mach-O parser warnings. The raw result and wheel hash are retained in
[the local campaign summary](protection-fuzz-wheel-local-2026-11-14-84e1202f.json)
and [its raw report](protection-fuzz-wheel-local-2026-11-14-84e1202f-macos.json).
This adds current-commit evidence for the local macOS host only; the
three-runner fuzz campaign is still running and platform parity remains open.

## Resolved blockers

- The latest differential workflow, run
  [`43534838628`](https://github.com/seifreed/r2morph/actions/runs/43534838628),
  completed 85/85 jobs on `72697b8b`. Core and extended campaigns classified
  23,892 executions across 22 passes, with 6,939 applications and zero errors,
  failed seeds, or semantic failures. The public corpus passed 360 samples;
  QEMU parity passed 1,005 VM fixtures; all five platform previews passed 73
  cases; and 48 fuzz shards completed 30,720 target runs with zero failures.
  This refreshes published correctness and cost evidence. It does not close
  the separate parity, all-analyzer, or resistance criteria: the previews are
  bounded, 22 decompiler maturity blockers remain, and the public static
  recovery run used radare2 only. The source reports are retained and
  hash-checked in
  [protection-differential-run-2026-11-14-43534838628.json](protection-differential-run-2026-11-14-43534838628.json).

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
  The current run `43339101882` has also completed its Windows PE (17 cases)
  and ARM32 (6 cases) preview jobs with zero failures, errors, or skips. Their
  hash-bound reports are recorded in `compatibility-corpus.md`; these bounded
  job results do not complete the run's full matrix or establish platform
  parity.
  In run `43340083394`, the five individual platform jobs have since passed
  their validators and produced 73 zero-failure JUnit cases. The retained
  per-job hashes are in
  [protection-platform-preview-run-2026-11-13-c45eb58e.json](protection-platform-preview-run-2026-11-13-c45eb58e.json).
  At this update, the workflow aggregate and its differential corpus jobs are
  still running; these reports therefore remain bounded preview evidence.
  Run [`43390828239`](https://github.com/seifreed/r2morph/actions/runs/43390828239)
  later completed 85/85 jobs on `acfc0995`: 22 passes had 23,892 classified
  core/extended runs with zero errors or semantic failures; public compatibility
  passed 360 samples, and VM parity passed 1,005 fixtures. All five platform
  previews passed 73 cases, but explicitly make no parity claim. The maturity
  evidence still contains 22 decompiler blockers. See the hash-bound
  [run report](protection-differential-run-2026-11-13-43390828239.json).
  A subsequent full workflow run [`43498875302`](https://github.com/seifreed/r2morph/actions/runs/43498875302)
  on `b012cd0a` reproduced the 23,892 core/extended classifications with zero
  semantic failures, plus 1,005/1,005 VM fixtures, 360 public corpus samples,
  and 73 passing cases across five preview platforms. Its retained aggregate is
  [protection-differential-run-2026-11-13-43498875302.json](protection-differential-run-2026-11-13-43498875302.json).
  The preview matrix leaves cross-platform parity unresolved; 22 decompiler
  blockers remain, so platform parity and generalized resistance stay open.
  On current `main` (`6fd35609`), run `43413931661` also completed the native
  wheel-installed macOS ARM64 and Windows PE preview suites: 35 and 17 cases,
  respectively, with zero failures, errors, or skips. Their raw JUnit files and
  hashes are recorded in
  [protection-platform-native-preview-run-2026-11-13-43413931661.json](protection-platform-native-preview-run-2026-11-13-43413931661.json).
  This refreshes two platform slices on current `main`; it does not provide the
  full five-platform aggregate or close cross-platform parity.

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
  A focused current-commit shard measured CodeVirtualization on nine repository
  fixtures. All nine transformations applied with zero unsupported functions,
  partial results, or pass errors. IDA Pro 9.5, Ghidra 12.2, angr, radare2,
  objdump, and the custom analyzer completed all nine measurements; Unicorn
  completed eight and lacked one instruction, while Binary Ninja and Triton
  remained unavailable on the host. There were zero analyzer errors or missing
  rows. The runner output hash is `e6a031f61f4fc86a474c241622ad7b052ad19e53a2c6328f75a5a37700c89dae`;
  the published report is separately bound to commit `4db66d94`. This adds
  current-commit evidence for the available tools but covers one pass and nine
  fixtures only; it does not close the full analyzer matrix or resistance gap.
  Evidence: [protection-adversarial-codevirtualization-2026-11-12-4db66d94-shard-12.json](protection-adversarial-codevirtualization-2026-11-12-4db66d94-shard-12.json)
  and [test_published_codevirtualization_adversarial_shard_12.py](../tests/unit/test_published_codevirtualization_adversarial_shard_12.py).
  A follow-up shard on the same source commit applied CodeVirtualization to
  nine more fixtures. IDA Pro 9.5, Ghidra 12.2, angr, Unicorn, radare2, objdump,
  and the custom analyzer completed 63/63 available runs with zero report
  error rows. angr emitted unsupported `amd64g_dirtyhelper_IN` and
  `amd64g_dirtyhelper_OUT` diagnostics, so its completed decompiler measurements
  remain bounded and do not prove semantic equivalence. Binary Ninja's license
  was invalid and Triton was unavailable, leaving 18/81 expected runs
  unavailable. The raw report and hash-bound
  summary are
  [protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13.json](protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13.json)
  and
  [protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13-summary.json](protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13-summary.json).
  This adds one pass-by-fixture slice and does not resolve the full matrix or
  resistance gap.
  A subsequent current-main run applied all 22 declared pass names to the same
  nine fixtures: 17 applied rows, 181 no-op rows, zero omissions, and zero
  pass errors. IDA Pro, Ghidra, angr, Unicorn, radare2, objdump, and the custom
  analyzer completed all 198 rows each. Binary Ninja and Triton were
  unavailable, leaving 396/1,782 expected analyzer runs incomplete. angr also
  emitted unsupported-dirty-helper and calling-convention diagnostics. The
  hash-bound reports are
  [protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13.json](protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13.json)
  and
  [protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13-summary.json](protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13-summary.json).
  This is a single fixture shard and does not close the all-sample analyzer
  matrix or establish general resistance.
  Exit criteria: complete the declared analyzer slots, resolve the 17 reported
  evidence blockers, and retain comparable results for all 22 passes.
  A second all-pass host shard at source `2c9be637` covered 11 fixtures and
  242 pass rows: 30 applied, 212 no-op, zero omitted, and zero failed. Seven
  analyzers completed all rows; Binary Ninja was blocked by license
  availability and Triton was not installed, leaving 484/2,178 expected
  analyzer slots unavailable. angr also reported unsupported dirty helpers,
  missing calling conventions, and unhooked addresses. See the hash-bound
  [raw report](protection-host-adversarial-allpasses-2026-11-13-2c9be637-shard-14.json)
  and [summary](protection-host-adversarial-allpasses-2026-11-13-2c9be637-shard-14-summary.json).
  This additional bounded shard does not close the full matrix or general
  resistance criterion.
  A third all-pass host shard at source `5806a27d` covered 10 fixtures and 220
  pass rows: 16 applied, 204 no-op, zero omitted, and zero failed. Six
  analyzers completed every row; Unicorn missed 22 rows due an unsupported
  fixture instruction, while Binary Ninja and Triton were unavailable for all
  rows. This left 462/1,980 analyzer slots unavailable. angr diagnostics
  included unsupported dirty helpers, unhooked addresses, and missing calling
  conventions. See the hash-bound
  [raw report](protection-host-adversarial-allpasses-2026-11-13-5806a27d-shard-15.json)
  and [summary](protection-host-adversarial-allpasses-2026-11-13-5806a27d-shard-15-summary.json).
  It is bounded evidence and does not close the analyzer matrix or general
  resistance criterion.
  A 32-shard host run at source `acfc0995` measured five additional ELF
  x86-64 fixtures across all 22 passes: 12 applications, zero pass errors or
  omissions, and 110 completed IDA Pro measurements. angr, radare2, objdump,
  Unicorn, and the custom analyzer also completed all 110 rows each. Binary
  Ninja was unavailable because the local license was invalid; Ghidra and
  Triton were unavailable on the host. The run completed 660/990 analyzer
  slots with zero tool errors and no missing rows. Its generated Linux corpus
  was not included on macOS. See the hash-bound
  [raw report](protection-host-adversarial-allpasses-2026-11-13-acfc0995-shard-14-32.json)
  and [summary](protection-host-adversarial-allpasses-2026-11-13-acfc0995-shard-14-32-summary.json).
  This fills one bounded IDA slice; all-analyzer coverage and general
  resistance remain open.
  A local shard at source `61f152e2` covered six repository fixtures across all
  22 passes: 12 applications, 120 no-ops, zero pass errors or omissions, and
  1,056 completed analyzer runs. Eight analyzers completed all 132 rows each;
  Binary Ninja was unavailable because its license was invalid, leaving
  132/1,188 analyzer slots unavailable. Generated Linux fixtures were not
  included on macOS. See the hash-bound
  [raw report](protection-host-adversarial-allpasses-2026-11-13-61f152e2-shard-16-32.json)
  and [summary](protection-host-adversarial-allpasses-2026-11-13-61f152e2-shard-16-32-summary.json).

  The next current-main shard at `b012cd0a` covered five repository fixtures
  across all 22 passes (110 rows): 10 applications, 100 no-ops, no omissions,
  and no pass errors. Eight analyzers completed each row; Binary Ninja was
  unavailable for all rows because its license was unavailable. Generated
  Linux fixtures were not included, and 16 passes had no application in this
  sample. The raw report and summary are
  [protection-host-adversarial-allpasses-2026-11-13-b012cd0a-shard-17-32.json](protection-host-adversarial-allpasses-2026-11-13-b012cd0a-shard-17-32.json)
  and
  [protection-host-adversarial-allpasses-2026-11-13-b012cd0a-shard-17-32-summary.json](protection-host-adversarial-allpasses-2026-11-13-b012cd0a-shard-17-32-summary.json).
  This bounded fixture slice does not close the all-analyzer or general
  resistance criteria.
  The following current-main shard at `eb1fa600` measured six more repository
  fixtures across all 22 passes (132 rows): 15 applications, zero omissions,
  and zero pass errors. IDA Pro 9.5 completed all 132 rows; angr, Ghidra,
  radare2, objdump, the custom analyzer, and Unicorn completed 902 tool rows
  overall. Binary Ninja was unavailable because its local license was invalid,
  Triton was unavailable on macOS ARM64, and Unicorn could not emulate one
  original/protected pair across 22 pass rows. There were no tool errors or
  missing rows. The generated Linux corpus was not included. The hash-bound
  report and summary are
  [protection-host-adversarial-allpasses-2026-11-14-eb1fa600-shard-18-32.json](protection-host-adversarial-allpasses-2026-11-14-eb1fa600-shard-18-32.json)
  and
  [protection-host-adversarial-allpasses-2026-11-14-eb1fa600-shard-18-32-summary.json](protection-host-adversarial-allpasses-2026-11-14-eb1fa600-shard-18-32-summary.json).
  This adds a bounded IDA slice, but leaves the all-analyzer and resistance
  criteria open.
  This adds a local Triton slice but leaves the all-analyzer matrix and general
  resistance criterion open.
  The full GitHub campaign at [run 43347265883](https://github.com/seifreed/r2morph/actions/runs/43347265883)
  did not aggregate: shard 12 hit the six-hour job timeout, leaving 15/16
  reports. The benchmark now partitions the same declared scope into 32 jobs
  to reduce per-job work. That scheduling change was not itself evidence of
  completion.
  The follow-up at source `5f02052e` completed the 32 shards and aggregate in
  [run 43526206403](https://github.com/seifreed/r2morph/actions/runs/43526206403)
  (33/33 jobs successful). It measured 362 corpus samples across all 22 passes
  (7,964 pass rows): 2,341 applied runs, zero pass errors, omissions, or missing
  rows. Seven of nine tools completed all 7,964 rows; 55,220/71,676 expected
  analyzer runs completed overall (77.04%), with 17 evidence blockers. Binary
  Ninja and IDA Pro were unavailable for all rows; Unicorn lacked support for
  528 fixture instructions; angr had three unavailable applied baseline pairs.
  The VM smoke covered 15 fixtures and ten seeds with semantic parity, distinct
  artifacts, handler/dispatcher/opcode diversity, and divergent tamper probes.
  Its automated report remains pending human adversarial review and does not
  establish general resistance. The core runtime and adversarial benchmark
  implementation files are unchanged on current `main`; the archived aggregate,
  three VM reports, hashes, and extracted counts are in
  [protection-adversarial-run-2026-11-14-43526206403.json](protection-adversarial-run-2026-11-14-43526206403.json)
  and [the compressed raw report](protection-adversarial-run-2026-11-14-43526206403.json.gz).
  This closes the shard-completion gap only;
  analyzer coverage and general resistance remain open.
  On the same wheel, a local macOS ARM64 rerun covered ten repository ELF
  fixtures and ten seeds. Semantic parity and the automated diversity, tamper,
  and bounded recovery checks passed; progressive growth was supported on
  seven of ten fixtures. Native ELF execution was unavailable on macOS and the
  five generated Linux fixtures were not included. The raw report and wheel-
  hash-bound summary are
  [protection-vm-resistance-local-2026-11-14-84e1202f-macos.json](protection-vm-resistance-local-2026-11-14-84e1202f-macos.json)
  and
  [protection-vm-resistance-local-2026-11-14-84e1202f.json](protection-vm-resistance-local-2026-11-14-84e1202f.json).
  Human review remains pending and general resistance remains unproven.

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
- RB-007: Independent human review records approval for commit
  `a111f923df43a66826b71ab70db8a484532fbf3b`. Later production changes make that
  approval stale for the current tree; the automated report now records
  `human_signoff: not-attested` and `release_decision: block-vm-milestone`.
  The release workflow requires a matching review of the final tree. Evidence map:
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

The current-main rerun at `134af4ff` is recorded in
[protection-fuzz-wheel-platform-2026-11-13-134af4ff.json](protection-fuzz-wheel-platform-2026-11-13-134af4ff.json)
and [workflow run 43331412474](https://github.com/seifreed/r2morph/actions/runs/43331412474).
It completed the same nine targets on all three runners (540,000 runs, zero
failures). This updates evidence freshness only; it does not close any of the
three open 1.0 criteria.

Commit `03984513` adds deterministic fuzzing of the VM instruction decoder. A
local Python 3.13.11 run covered ten targets with 5,000 cases each (50,000
target runs, zero failures). Its raw output and hash-bound summary are
[protection-fuzz-vm-decoder-2026-11-14-03984513-output.json](protection-fuzz-vm-decoder-2026-11-14-03984513-output.json)
and
[protection-fuzz-vm-decoder-2026-11-14-03984513.json](protection-fuzz-vm-decoder-2026-11-14-03984513.json).
The installed-wheel campaign for the same commit then passed on Ubuntu,
macOS ARM64, and Windows in
[workflow run 43527087277](https://github.com/seifreed/r2morph/actions/runs/43527087277):
150,000 target runs across three runners, zero failures, and 103 counted
recoverable Mach-O parser warnings per runner. Its per-runner reports and
hash-bound aggregate are
[protection-fuzz-vm-decoder-platform-2026-11-14-03984513.json](protection-fuzz-vm-decoder-platform-2026-11-14-03984513.json).
This verifies wheel-backed fuzz execution on the three declared runners; it
does not establish semantic equivalence, platform parity, or general
resistance.

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
