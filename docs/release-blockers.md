# Release Blockers

This ledger records the remaining blockers from the current release-hardening
review. It is not a feature roadmap and must not be read as a support claim.
The machine-readable [1.0 readiness ledger](one-zero-readiness.json) records
the evidence requirements and keeps stable-major releases blocked while any
criterion remains open or in progress.

## Current-source partial differential snapshot — 2026-11-25

Workflow
[`45528080704`](https://github.com/seifreed/r2morph/actions/runs/45528080704)
ran on source `da383ba850ad71c4a58cf68d15e1a35dff667770`. At capture, 51 of 83
jobs had succeeded, 15 were active, 17 were queued, and none had failed. The run
was later canceled before completion. The captured artifacts include six
platform smoke slices with 78/78 cases passing;
23 of 24 VM semantic shards with 963/963 fixture-seed cases passing; and 19 of
48 Linux ELF x86-64 shard-seed cells for each of the core and extended matrices.
The captured core rows classified 4,320 runs and the extended rows 5,184 runs;
each set had complete evidence and zero errors or semantic failures. Six listed
artifacts were not downloaded at capture. The
[hash-bound partial manifest](protection-differential-partial-2026-11-25-45528080704/summary.json)
and regression test preserve exact artifacts and limits. This is not the
campaign aggregate or full platform/pass parity; all-named-analyzer,
cross-platform-parity, and generalized-resistance gates remain open.

## Current-source CI and continuous fuzz validation — 2026-11-25

GitHub CI run
[`45599431923`](https://github.com/seifreed/r2morph/actions/runs/45599431923)
completed all 19 jobs successfully on source
`9c9177952decf745674715563fbfa8e73a92a090`. It covered unit, integration,
stable-product, installed-wheel, property/fuzz, lint, type-check, and the
Ubuntu, macOS ARM64, macOS Intel, and Windows Python 3.12–3.14 matrix. This
includes the Intel macOS Mach-O regression that exposed the unsafe NOP padding
replacement before the fix. The matching continuous-fuzz workflow
[`45599431832`](https://github.com/seifreed/r2morph/actions/runs/45599431832)
passed all three platform jobs on the same source.

These runs validate the tested package paths and bounded fuzz targets for this
commit. They do not establish full pass-by-platform parity, availability of all
named analyzers, or generalized resistance. The current-source full
differential campaign [`45602419475`](https://github.com/seifreed/r2morph/actions/runs/45602419475)
is still running; the three 1.0 readiness gates remain open.

## Current-source CI validation — 2026-11-24

GitHub CI run
[`45505954601`](https://github.com/seifreed/r2morph/actions/runs/45505954601)
completed all 19 jobs successfully on source
`0a9a9c35aaa54f80b65f222213713b78f6757e80`, with no failed or skipped jobs.
The run covered unit, integration, stable-product, installed-wheel, property
and fuzz tests; lint, type checking, release-contract and support-matrix
validation, Bandit, and `pip-audit`; and Ubuntu, macOS ARM64, macOS Intel, and
Windows runners on Python 3.12, 3.13, and 3.14. The broad Ubuntu/Python 3.12
coverage job also passed. The matching continuous-fuzz workflow
[`45505954616`](https://github.com/seifreed/r2morph/actions/runs/45505954616)
passed all three platform jobs on the same source commit.

These checks validate the current dependency and package configuration and
regression suites; they do not establish all-pass analyzer availability,
binary-format/architecture parity, or generalized resistance. The separate
adversarial benchmark `45488041450` later completed on source
`4d456ac818845e6fdd92ccce9411dc60612d7105`; it used the older dependency stack
and is superseded for current analyzer results by the 2026-11-25 campaign below.
The three 1.0 readiness gates remain open.

## Completed differential campaign — 2026-11-25

Workflow [`45544822953`](https://github.com/seifreed/r2morph/actions/runs/45544822953)
completed all 86 jobs successfully on pinned source
`1dabf440aa7b2a9443a67c692fa14c03d24c9fe5`. The Linux ELF x86-64 core matrix
classified 10,860 runs across ten passes (3,480 applied, 7,380 omitted); its
twelve extended passes classified 13,032 runs (3,406 applied, 9,626 omitted).
Every row had complete evidence, with zero errors or semantic failures. The run
also passed 2,208 composition cases, 370 public compatibility samples with
2,220 radare2 recovery measurements, 1,005/1,005 VM fixture-seed cases with
all QEMU oracle pairs matching, and 78/78 cases in six bounded platform preview
slices. The public compatibility report is byte-identical to the previous
campaign's aggregate. The [hash-bound manifest](differential-run-2026-11-25-45544822953.json)
records artifact identities, digests, and scope; the
[platform summary and JUnit reports](protection-platform-preview-2026-11-25-45544822953.json)
pin each platform slice. The maturity report still has 22 decompiler blockers;
public-corpus optional decompiler runners were omitted. This campaign does not
establish universal correctness or full pass-by-platform parity. The
all-named-analyzers, cross-platform-parity, and published-resistance gates
remain open.

## Completed adversarial analyzer and VM campaign — 2026-11-24

Adversarial workflow
[`45488041450`](https://github.com/seifreed/r2morph/actions/runs/45488041450)
completed all **32 analyzer shards and the aggregate job** successfully
(33/33 jobs) on source `4d456ac818845e6fdd92ccce9411dc60612d7105`. The merged
report covers 362 Linux ELF x86-64 fixtures, including 200 generated C/C++
fixtures, across 22 passes and 7,964 pass runs. All 71,676 analyzer slots were
present, with 55,220 completed, 16,456 unavailable, and zero missing rows or
tool errors. Binary Ninja and IDA Pro were unavailable for all 7,964 rows;
Unicorn could not emulate 528 unsupported-instruction rows. Code virtualization
applied to all 362 samples and reported 14 functions with unsupported
exception/unwinding or SSA-liveness capabilities; this is not a claim of full
function coverage.

The automated VM smoke covered 15 fixtures and 10 seeds. It recorded semantic
parity, diverging tamper probes, and opcode, dispatcher, handler, and grammar
diversity; progressive bytecode growth was supported for 6 fixtures. There
were no exact normalized cross-seed matches, but 328/2,295 comparisons exceeded
the 0.8 similarity threshold (maximum 0.933). The campaign explicitly marks
human adversarial review as pending, so these bounded measurements do not
establish generalized resistance.

This run predates the current dependency bounds: it used source requirements
`angr>=9.3.2` and `pycparser>=3.1,<3.2`; `main` now requires `angr>=10.0.7`
and `pycparser>=3.11,<3.12`. The campaign therefore does not validate analyzer
behavior under the current dependency stack. It also covers Linux ELF x86-64
only. The hash-bound [summary](protection-adversarial-run-2026-11-24-45488041450-summary.json),
[merged analyzer report](protection-adversarial-run-2026-11-24-45488041450.json.gz),
[VM resistance report](protection-vm-resistance-run-2026-11-24-45488041450.json.gz),
[seed-diversity report](protection-vm-seed-diversity-2026-11-24-45488041450.json),
[bytecode-grammar report](protection-vm-bytecode-grammar-2026-11-24-45488041450.json),
and [regression test](../tests/unit/test_published_adversarial_run_45488041450.py)
preserve the evidence and its limits. All three 1.0 readiness gates remain open.

## Current-dependency adversarial analyzer and VM campaign — 2026-11-25

Workflow [`45548803519`](https://github.com/seifreed/r2morph/actions/runs/45548803519)
completed all 32 analyzer shards and its aggregate job (33/33) on source
`1dabf440aa7b2a9443a67c692fa14c03d24c9fe5`, which uses the current dependency
bounds. The merged report covers 362 Linux ELF x86-64 fixtures, including 200
generated C/C++ fixtures, across all 22 passes and 7,964 pass runs. All 71,676
expected analyzer slots were present: 55,220 completed, 16,456 unavailable,
and zero errored or missing rows. `angr`, custom, Ghidra, objdump, radare2, and
Triton completed all 7,964 rows. Unicorn completed 7,436 rows and could not
emulate 528 unsupported-instruction rows. Binary Ninja and IDA Pro were
unavailable for all 7,964 rows. Code virtualization applied to all 362
fixtures and virtualized 639 functions; 14 functions reported unsupported
exception/unwinding or SSA-liveness capabilities.

The attached maturity evidence records 46/46 composition cases without
failure, error, or skip for its measured scope. Separately, the automated VM
smoke covered 15 fixtures and ten seeds, preserved semantic parity, and saw all
tamper probes diverge. Progressive bytecode growth was supported for 6/15
fixtures. There were no exact normalized cross-seed matches; 328/2,295
comparisons exceeded the 0.8 similarity threshold (maximum 0.933). The report
still marks human adversarial review pending. These bounded results do not
establish full analyzer availability, platform parity, or generalized
resistance.

The [hash-bound summary](protection-adversarial-run-2026-11-25-45548803519-summary.json),
[merged report](protection-adversarial-run-2026-11-25-45548803519.json.gz),
[maturity report](protection-maturity-adversarial-run-2026-11-25-45548803519.json.gz),
[VM resistance report](protection-vm-resistance-run-2026-11-25-45548803519.json.gz),
[seed-diversity report](protection-vm-seed-diversity-run-2026-11-25-45548803519.json),
[bytecode-grammar report](protection-vm-bytecode-grammar-run-2026-11-25-45548803519.json),
and [regression test](../tests/unit/test_published_adversarial_run_45548803519.py)
pin the artifacts and limits. The analyzer and published-resistance gates
remain open.

## Current-source partial differential snapshot — 2026-11-20

Workflow
[`44661095783`](https://github.com/seifreed/r2morph/actions/runs/44661095783)
ran on source `f319f1e4c47f80b678b8a397dcdbcb0fa1d17f87`. At the pinned
snapshot, 16 of 81 jobs had succeeded, 13 were active, 52 were queued, and zero
had failed. Windows PE and ELF ARM32, ARM64, and x86-32 passed 39 selected
cases with no failures, errors, or skips. The macOS ARM64 job and the full
matrix had not completed.

One core shard classified 230 rows across 10 passes (76 applied; 154 omitted
as ineligible); one extended shard classified 276 rows across 12 passes (71
applied; 205 omitted as ineligible). Both recorded complete evidence for every
row and zero errors or semantic failures. Eleven VM semantic shards passed
461/461 fixture-seed cases on Linux ELF x86-64. These are partial slices, not
full corpus, platform, or resistance conclusions. The
[hash-bound summary and reports](protection-differential-partial-2026-11-20-44661095783/summary.json)
and [regression test](../tests/unit/test_published_differential_partial_44661095783.py)
preserve and verify the exact evidence. The parity, all-analyzer, and published
resistance criteria remain open.

## Completed differential campaign on pinned source — 2026-11-20

The manually dispatched workflow
[`44676092171`](https://github.com/seifreed/r2morph/actions/runs/44676092171)
completed all 86 jobs successfully on source `2f54c47ee08dee65a2aeda406ee4bd8a3a78bbfc`.
Its merged artifact reports 10,860 core and 13,032 extended classifications,
all with complete evidence, zero failures, and zero errors. A generated public
compatibility corpus passed all 360 samples across six passes; 44 directional
composition pairs completed 2,208 cases with no failures or errors. The
[summary](differential-run-2026-11-20-44676092171-summary.json) pins the merged
artifact digest, report hashes, and aggregate counts. The evidence belongs to
that source revision, does not claim results for later code changes, and does
not establish parity for PE, Mach-O, ARM, AArch64, or x86. The named-analyzer
and published-resistance gates remain open.

## Local installed-wheel release validation — 2026-11-16

The wheel and source distribution for `0.4.0-alpha.3` were built from source
commit `2c50cff3d40c9a37831f4725c3222e8c7ed6a355` on Python 3.12.16/macOS
ARM64. Twine validated both artifacts, the isolated installed wheel imported
the public API and reported the expected CLI version, and the complete
release-suite command passed with **7,006 passed, 226 skipped, 0 failed**.
`pip-audit` generated a CycloneDX SBOM and found no known vulnerabilities.
Wheel, sdist, and SBOM SHA-256 values are pinned in the
[local release validation manifest](release-validation-local-2026-11-16-2c50cff3.json).

This is a local package-validation run, not the release workflow: it does not
create GitHub provenance or publish to PyPI, and it ran on macOS ARM64 rather
than the workflow's Linux runner. Stable release remains blocked by the open
1.0 readiness criteria and the missing human approval for the exact source
tree. The matching GitHub CI run
[`43914393719`](https://github.com/seifreed/r2morph/actions/runs/43914393719)
passed all 15 jobs on the same source commit.

## Local package validation — 2026-11-20

Source commit `5f414ed0584f991588642554d9bd1ad498ad91bd` built the
`0.4.0-alpha.3` wheel and sdist on Python 3.13.17/macOS arm64. Twine accepted
both artifacts; the installed wheel imported from an isolated environment,
reported its CLI version, and passed the 318-test package smoke. The complete
checkout unit suite passed 5,845 tests with 12 skips. The audit of
`requirements.txt` found zero known vulnerabilities and generated a 114-component
CycloneDX SBOM. The [manifest](release-validation-local-2026-11-20-5f414ed.json)
pins wheel, sdist, and SBOM hashes. This local run does not verify coverage
thresholds, replace the pending GitHub CI result, generate GitHub provenance,
publish to PyPI, or close the exact-tree review and 1.0 readiness criteria.

## Current-source adversarial campaign — 2026-11-18

Workflow
[`44142495055`](https://github.com/seifreed/r2morph/actions/runs/44142495055)
completed all 32 shard jobs and its aggregate on source commit
`b656b0dcd34af43e13db7e9b117ea401c2fbe6fd`. The campaign covered 362 ELF
x86-64 samples, 22 passes, and 7,964 pass rows. It observed all 71,676 expected
analyzer rows: 55,220 completed (77.04%), 16,456 unavailable, zero errors, and
zero missing rows. Angr, the custom analyzer, Ghidra, objdump, radare2, and
Triton completed every row. Unicorn completed 7,436 rows and reported 528
unavailable because the installed emulator did not support instructions in
those fixtures. Binary Ninja was unavailable for all 7,964 rows because its
module/license was absent; IDA Pro was unavailable for all rows because `idat`
was absent. The all-named-analyzers gate remains open.

The automated VM smoke covered 15 fixtures and ten seeds. Semantic parity,
distinct output, opcode/dispatcher/handler/grammar diversity, and tamper-probe
divergence were observed; progressive growth was supported on six fixtures.
There were no exact normalized cross-seed matches, while 388/2,295 comparisons
exceeded 0.8 similarity (maximum 0.927). These finite generated-output
observations are not attack-cost measurements or proof of generalized
resistance. The campaign report keeps human adversarial review pending. Marc
Rivero Lopez's independent approval applies to commit
`a111f923df43a66826b71ab70db8a484532fbf3b`; later production changes are outside
that review, so matching human signoff and published general resistance remain
open.

The independent automated second pass
[`44166019050`](https://github.com/seifreed/r2morph/actions/runs/44166019050)
passed all 28 evidence checks on the same source. It records
`human_signoff: not-attested` and blocks the VM milestone pending a matching
human review. The updated report, review-run manifest, benchmark summary,
archive, and regression contract are
[`independent-review.json`](independent-review.json),
[`protection-independent-review-run-2026-11-18-44166019050.json`](protection-independent-review-run-2026-11-18-44166019050.json),
[`protection-adversarial-2026-11-18-44142495055-summary.json`](protection-adversarial-2026-11-18-44142495055-summary.json),
[`complete shard archive`](protection-adversarial-2026-11-18-44142495055.tar.gz),
and [`test_published_adversarial_campaign_44142495055.py`](../tests/unit/test_published_adversarial_campaign_44142495055.py).

Workflow
[`44223496306`](https://github.com/seifreed/r2morph/actions/runs/44223496306)
completed all 32 analyzer shards on source `1cf52005310a527b86c68b4ff713ce248f1432d7`.
Production files under `r2morph/` and `scripts/` are unchanged through
`42a07930b4140d3598a8dd509e67cc229dadb86a`. The corpus contained 362 fixtures,
including 200 generated ELF/C++ fixtures, and covered all 22 passes: 7,964/7,964
pass rows and 71,676/71,676 analyzer slots, with 2,343 applied passes, zero
errors, and zero missing rows. 55,220 analyzer rows completed; Binary Ninja and
IDA Pro were unavailable for all rows, and Unicorn could not run 528 unsupported
instruction rows. Ghidra and Triton completed all 7,964 rows. The accompanying
VM smoke ran 15 fixtures and ten seeds, but its human adversarial review remains
pending. This is bounded analyzer and generated-output evidence, not generalized
resistance. The [hash-bound summary](protection-current-production-adversarial-2026-11-18-44223496306-summary.json),
[raw shard and VM archive](protection-current-production-adversarial-2026-11-18-44223496306.tar.gz),
and [regression test](../tests/unit/test_published_current_production_adversarial_44223496306.py)
preserve scope and limitations; both release gates remain open.

## Current-source local fuzz run — 2026-11-18

On source commit `0491ba06a09240eee7b36241cc4d8e4b040a7a83`, the local
Python 3.14.10/macOS ARM64 campaign ran 5,000 deterministic cases against each
of ten parser, assembler, VM, relocation, and binary-rewriter targets: 50,000
target runs, zero failures, and 106 retained recoverable Mach-O parser
diagnostics. The [hash-bound manifest](continuous-fuzz-local-2026-11-18-0491ba06.json),
[raw report](continuous-fuzz-local-2026-11-18-0491ba06-report.json), and
[regression contract](../tests/unit/test_published_local_continuous_fuzz_0491ba06.py)
pin the source and report. This single-host bounded run does not establish
arbitrary-input semantic equivalence, cross-platform parity, or adversarial
resistance; the related readiness gates remain open.

### Current-source local IDA sample — 2026-11-18

On source `6d8d450a2cabe27fdfa723b7d911ce9a5a15f35c`, a local benchmark applied
`CodeVirtualization` to `elf_vm_arith_x86_64`. IDA Pro completed decompilation
for both original and protected binaries; Unicorn returned exit code 45 for
both. Six of nine analyzer slots completed with zero errors; Binary Ninja was
unavailable because no valid license was installed, and Ghidra and Triton were
unavailable in this local environment. This single fixture does not close the
all-named-analyzers gate. The [hash-bound summary](protection-adversarial-current-main-local-2026-11-18-6d8d450a-summary.json),
[raw report](protection-adversarial-current-main-local-2026-11-18-6d8d450a.json),
and [regression test](../tests/unit/test_published_local_adversarial_current_main_6d8d450a.py)
preserve the measurement and limits.

## Latest completed CI validation

CI run [`43701797813`](https://github.com/seifreed/r2morph/actions/runs/43701797813)
completed all 15 jobs successfully on source commit `670a967c`. It covered the
installed-wheel smoke, integration and product tests, property/fuzz checks,
type checking, linting, the Linux, macOS, and Windows Python matrix, and broad
Linux coverage on Python 3.12. Changes through audited source `fc21d286` only
update the Windows differential workflow and its regression contracts; no
package runtime code changed.

On `fc21d286`, the local full suite passed on Python 3.14 with 6,923 passed,
225 skipped, and 82.15% coverage. CI run
[`43703694686`](https://github.com/seifreed/r2morph/actions/runs/43703694686)
then completed all 15 jobs successfully, including Linux / Python 3.12. The
matching Windows PE differential workflow
[`43703694688`](https://github.com/seifreed/r2morph/actions/runs/43703694688)
and dependent adversarial benchmark
[`43703700102`](https://github.com/seifreed/r2morph/actions/runs/43703700102)
were cancelled before completion. For source `1cf69382`, CI
[`43708730522`](https://github.com/seifreed/r2morph/actions/runs/43708730522)
is running, and differential workflow
[`43708730512`](https://github.com/seifreed/r2morph/actions/runs/43708730512)
is queued; its dependent adversarial benchmark
[`43708735434`](https://github.com/seifreed/r2morph/actions/runs/43708735434)
was cancelled and awaits the differential workflow result. These results do
not claim complete current-head CI or close the analyzer-coverage,
cross-platform-parity, and resistance criteria.

An additional one-fixture differential run on source `49649d9e` applied
`CodeVirtualization` to `elf_vm_varargs_x86_64` under Linux arm64 with QEMU
x86-64 user emulation. The original and transformed programs both returned
`69`; stdout and stderr hashes matched, Unicorn agreed, and the run recorded
100% complete-evidence coverage. The protected output grew by 24,525 bytes,
with 85 additional instructions, 11 basic blocks, and 17 CFG edges. A separate
manual decompiler check produced pseudocode for the original variadic function
and the protected dispatcher; it is explicitly excluded from automated
analyzer-slot counts. The hash-bound [summary](protection-differential-varargs-local-2026-11-15-49649d9e-summary.json)
and [raw report](protection-differential-varargs-local-2026-11-15-49649d9e.json)
retain the measurements. This is one emulated fixture and one applied pass,
not native x86-64 platform parity or generalized resistance; the corresponding
readiness criteria remain open.

On Python 3.14.10, the full suite at `49649d9e` passed with 6,931 passed,
225 skipped, and 82.14% coverage. The focused published-evidence and release
gate checks passed again after adding the hash-bound artifacts.

The IDA adapter now preserves decompiler outcomes as completed, unavailable,
error, or partial and records only bounded error type/count fields. It no
longer turns a decompiler exception into zero-valued metrics. The regression
contract is `tests/unit/test_adversarial_ida_decompiler_result.py`; native
headless execution was not available during that earlier run because `idat`
was not on `PATH`, so it added no analyzer coverage or resistance evidence.
The full Python 3.14.10 suite with this adapter update passed 6,936 tests,
skipped 225, and reached 82.15% coverage; the five focused IDA result tests
also pass independently.

A fresh local run on source `1f783f57` located IDA 9.5 in its application
bundle and applied `CodeVirtualization` to `elf_vm_arith_x86_64`. IDA and
Ghidra 12.2 both completed decompilation; angr, radare2, objdump, Unicorn, and
the custom analyzer also completed, with no tool errors or missing rows.
Unicorn returned 45 for both original and transformed binaries. Binary Ninja
reported an unavailable license to the benchmark process, while Triton was
not installed on this macOS ARM64 host. The hash-bound [summary](protection-adversarial-current-main-local-2026-11-15-1f783f57-summary.json)
and [raw report](protection-adversarial-current-main-local-2026-11-15-1f783f57.json)
retain the results. This is one fixture and one applied pass; all-analyzer
coverage and generalized resistance remain open.

The full local suite for the evidence update passed with 6,943 passed, 225
skipped, and 82.14% coverage under Python 3.14.10. Black, Ruff, mypy, and
Bandit passed on a clean worktree; pip-audit reported no known vulnerabilities
for the fully resolved Linux/Python 3.13 dependency set, including optional
extras.

### Native Mach-O ARM64 differential rerun

On the current source commit `7d3e5946`, macOS ARM64 with Python 3.14.10 and
Clang 23.1.5 ran the five selected native execution cases in
`tests/integration/test_mutation_nop_insertion_arm64.py` under `-W error`:
NOP insertion, constant unfolding, instruction expansion, instruction
substitution, and NOP-plus-substitution composition all passed. The
[hash-bound report](protection-platform-macos-arm64-local-2026-11-16-7d3e5946.json)
records the fixture and test-source hashes, command, outcomes, and limitations;
the report contract is checked by
`tests/unit/test_published_native_macho_arm64_7d3e5946.py`. Seven other cases in
the module were deselected. This is one native host and five selected cases; it
does not close full Mach-O ARM64 pass parity or cross-platform parity.

### Current-main native Mach-O ARM64 integration module

On source `848d0f5b45338af97514a6c1a3a6e13bc4658e49`, macOS ARM64 with Python
3.13.11 and Clang 23.1.5 ran the complete
`tests/integration/test_mutation_nop_insertion_arm64.py` module with warnings
treated as errors. All 12 cases passed, including native execution comparisons,
compiled control-flow and memory fixtures, encoding-change checks, and rejection
of an unrepresentable immediate. The hash-bound
[report](protection-platform-macos-arm64-local-2026-11-16-848d0f5b.json) records
the exact test and fixture hashes. This is bounded evidence for one host and
one existing test module; it does not establish full Mach-O parity or close the
cross-platform readiness criterion.

### Current-main native Mach-O ARM64 string-obfuscation smoke

CI run [`45477619052`](https://github.com/seifreed/r2morph/actions/runs/45477619052)
tested source `a4f4dcba12020cda4fa7717c4361c027d4b09081` on macOS ARM64 with
Python 3.12. The dedicated generated-fixture case passed, confirming that the
unreferenced evidence string was mutated, the `puts("hello")` string stayed
intact, ad-hoc signing verified, and native output matched. The
[hash-bound report](protection-macho-arm64-string-2026-11-24-a4f4dcba.json)
pins the test-source and JUnit hashes; the
[JUnit report](protection-macho-arm64-string-2026-11-24-a4f4dcba.xml) contains
one passing case. Its contract is checked by
`tests/unit/test_published_native_macho_arm64_string_20261124.py`. This is a
single bounded check for one pass and does not establish full Mach-O ARM64 pass
parity or close the cross-platform readiness criterion.

### Current-source native Mach-O x86-64 smoke

The macOS Intel job in differential workflow
[`45480009561`](https://github.com/seifreed/r2morph/actions/runs/45480009561),
on source `a4f4dcba12020cda4fa7717c4361c027d4b09081`, passed all three native
Mach-O x86-64 cases: instruction substitution, register substitution, and
string obfuscation. The
[hash-bound report](protection-macho-x86-64-native-2026-11-24-a4f4dcba.json)
records the job, artifact, source test hash, and JUnit hash; the
[JUnit report](protection-macho-x86-64-native-2026-11-24-a4f4dcba.xml) has zero
failures, errors, or skips. This is bounded execution evidence for three passes
on one macOS Intel runner. It does not establish full Mach-O pass parity or
close the cross-platform readiness criterion.

### Selected current-source platform differential jobs — 2026-11-25

Six completed preview jobs from differential workflow
[`45517036412`](https://github.com/seifreed/r2morph/actions/runs/45517036412)
ran against source commit `7a278ceaea15a8872a00b9c0d75ed6d2d8dddd6`. Their
JUnit artifacts contain 78 passing cases with zero failures, errors, or skips:
ELF x86-32 (8), ELF ARM32 (6), ELF ARM64 (7), macOS ARM64 (36), macOS x86-64
(3), and Windows PE (18). The raw JUnit reports, GitHub artifact IDs and ZIP
digests, and per-report SHA-256 values are pinned in
[`platform-differential-preview-2026-11-25-45517036412.json`](platform-differential-preview-2026-11-25-45517036412.json)
and checked by
[`test_published_platform_differential_preview_45517036412.py`](../tests/unit/test_published_platform_differential_preview_45517036412.py).
This is a partial snapshot: the other jobs in the workflow had not finished
when it was recorded. The selected checks are bounded previews and do not
establish full pass-by-platform parity or close the `cross_platform_parity`
1.0 criterion.

### Partial cross-platform jobs on current package code

Differential workflow run [`43949336892`](https://github.com/seifreed/r2morph/actions/runs/43949336892)
ran on source `6c60d58d186fc7725465313b79ce488dee1ee0c4`. Five dedicated
preview jobs completed successfully: macOS ARM64 (37 tests), Windows PE (18),
ELF ARM32 (6), ELF ARM64 (7), and ELF x86-32 (8). All 76 JUnit cases passed
with no failures, errors, or skips. The individual [JUnit reports](cross-platform-differential-macos-arm64-43949336892.xml),
[Windows report](cross-platform-differential-windows-pe-43949336892.xml),
[ARM32 report](platform-elf-arm32-43949336892.xml),
[ARM64 report](platform-elf-arm64-43949336892.xml),
[x86-32 report](platform-elf-x86-32-43949336892.xml), and the
[hash-bound summary](protection-platform-partial-run-2026-11-16-43949336892.json)
preserve the initial evidence snapshot. The full workflow has since completed
successfully: all 85 jobs passed, and its [platform aggregate](platform-evidence-summary-43949336892.json)
reports five complete targets and 76/76 passing required cases with no failures,
errors, skips, or missing required cases. The [completion manifest](protection-platform-completed-run-2026-11-16-43949336892.json)
pins this result to the aggregate hash. These bounded preview tests do not
establish full pass-by-platform parity or close the `cross_platform_parity`
1.0 criterion.

### Differential corpus and extended-pass campaign

Differential workflow [`43835267898`](https://github.com/seifreed/r2morph/actions/runs/43835267898)
completed successfully on source commit `7d3e5946`. The Linux ELF x86-64 core
campaign covered all 10 core passes and 1,086 complete-evidence rows per pass;
the separately merged extended campaign covered all 12 additional passes with
the same row count. Both reports recorded 100% complete-evidence coverage and
zero errors, semantic failures, or runtime-observable failures. Applied runs
were fewer than evidence rows where passes explicitly omitted ineligible
samples. The compact
[hash-bound summary](protection-differential-run-2026-11-16-43835267898.json)
pins the source commit, per-pass outcomes, and hashes of the raw report
members. The campaigns do not close cross-platform parity: the core report
still scopes platform gaps to PE, Mach-O, ARM, AArch64, and x86, and they do
not establish analyzer completeness or generalized resistance.

## Current-main continuous fuzz campaign

The latest main-push workflow
[`44683267033`](https://github.com/seifreed/r2morph/actions/runs/44683267033)
passed on source commit `24d68c8c2bffd6695df205fc60f64dfe619f0ab1` across
macOS 15, Ubuntu, and Windows. Each runner built and installed the package
wheel, then ran 5,000 deterministic cases against each of ten targets, for
150,000 target runs total and zero failures. Each report retained 103
`macho_load_commands.warning` diagnostics. The raw reports, workflow artifact
IDs and SHA-256 digests, source-script hash, and limits are pinned in the
[summary](continuous-fuzz-2026-11-20-44683267033-summary.json) and its three
platform reports. This bounded campaign does not establish arbitrary-input
semantic equivalence, exhaustive fuzz coverage, complete platform parity, or
independent adversarial validation; those gates remain open.

Workflow run [`43654009381`](https://github.com/seifreed/r2morph/actions/runs/43654009381)
passed on source commit `7374619a` across Ubuntu, macOS, and Windows. Each
platform installed and tested the built wheel, then ran 5,000 deterministic
cases against each of 10 targets: 150,000 target runs total with zero failures.
Reports and SHA-256 digests are retained in the
[campaign summary](continuous-fuzz-2026-11-14-43654009381-summary.json) and its
three platform reports. The optional native Keystone installation ran only on
macOS; all platforms still recorded 5,000 assembly target runs. This closes
the current parser/VM/rewriter fuzzing evidence gap for those bounded inputs,
but does not establish arbitrary-input semantic equivalence or independent
adversarial validation.

A later run [`43666015524`](https://github.com/seifreed/r2morph/actions/runs/43666015524)
passed on source commit `f8586a1b` across the same three runners. It repeated
the 5,000-case, 10-target campaign on the installed wheel: 150,000 target runs
total and zero recorded failures. Each report records 103
`macho_load_commands.warning` diagnostics; these remain visible and are not
counted as campaign failures. The hash-bound
[summary](continuous-fuzz-2026-11-15-f8586a1-summary.json) and the retained
[Ubuntu](continuous-fuzz-2026-11-15-f8586a1-ubuntu.json),
[macOS](continuous-fuzz-2026-11-15-f8586a1-macos.json), and
[Windows](continuous-fuzz-2026-11-15-f8586a1-windows.json) reports establish
bounded multi-platform fuzzing for this implementation revision. They do not
establish arbitrary-input semantic equivalence, cross-platform behavioral
parity, or independent adversarial validation.

A second manually dispatched run [`43672705546`](https://github.com/seifreed/r2morph/actions/runs/43672705546)
used seed `20261115` on source commit `09310435`, with the same 5,000 cases per
target on Ubuntu, macOS, and Windows. All 150,000 target runs completed without
failures. The reports recorded 108 `macho_load_commands.warning` diagnostics
per platform. Their report hashes and source revision are retained in the
[second-seed summary](continuous-fuzz-2026-11-15-09310435-summary.json) and its
[Ubuntu](continuous-fuzz-2026-11-15-09310435-ubuntu.json),
[macOS](continuous-fuzz-2026-11-15-09310435-macos.json), and
[Windows](continuous-fuzz-2026-11-15-09310435-windows.json) reports. This
independent seed broadens bounded fuzz input coverage; it does not establish
arbitrary-input semantic equivalence, cross-platform parity, or independent
adversarial validation.

A third run [43678223817](https://github.com/seifreed/r2morph/actions/runs/43678223817)
completed on source commit `0e39d3ab5c24ec9100d602986f1cac9aa54ffa88`, using
seed `20260827`. Ubuntu, macOS, and Windows each ran 5,000 cases against all
10 targets, totaling 150,000 target runs with zero failures. Each report
retained 103 recoverable `macho_load_commands.warning` diagnostics. The
hash-bound [summary](continuous-fuzz-2026-11-15-0e39d3a-summary.json) and
[Ubuntu](continuous-fuzz-2026-11-15-0e39d3a-ubuntu.json),
[macOS](continuous-fuzz-2026-11-15-0e39d3a-macos.json), and
[Windows](continuous-fuzz-2026-11-15-0e39d3a-windows.json) reports establish
another bounded three-platform fuzz campaign. They do not establish arbitrary
input semantic equivalence, cross-platform behavioral parity, or independent
adversarial validation.

Continuous fuzz workflow [`43719827578`](https://github.com/seifreed/r2morph/actions/runs/43719827578)
also passed on source `ec0cfa8e` across Ubuntu, macOS, and Windows. Each runner
completed 5,000 cases against each of 10 targets: 150,000 target runs total,
with zero failures. The three reports and their SHA-256 hashes are pinned in
the [summary](continuous-fuzz-2026-11-15-43719827578-summary.json). The
Windows JSON is stored with normalized LF line endings; its original artifact
SHA-256 is also preserved in the summary. Each platform retained 103
`macho_load_commands.warning` diagnostics for malformed inputs; they remain
visible and are not counted as campaign failures. This
bounded run adds current-source fuzz evidence but does not prove arbitrary
input equivalence or cross-platform behavioral parity.

The handler generator was re-measured on source commit `f8586a1b` across 32
seeds, with 255 handlers per generated interpreter. All 32 opcode assignments
differed, both dispatcher variants occurred, and there were zero exact
normalized collisions within or across seeds. The nearest-handler similarity
mean was `0.723` and `3,439` of `7,905` comparisons were at least `0.8`, so
zero exact matches do not imply low structural similarity. This campaign
measures one interpreter per seed. A separate current-source run on the same
implementation commit `f8586a1b` then covered 10 ELF x86-64 fixtures across 32
seeds each: all 320 artifacts were distinct, emulator-observed exit codes
matched their baselines, while tamper divergence was not established: native
execution was unavailable and all tampered native exit codes were missing.
Every fixture had zero exact normalized handler collisions
across and within seeds. Opcode, dispatcher, and bytecode grammar diversity
were observed; progressive bytecode growth was supported on 7 of the 10
fixtures. The hash-bound [campaign summary](protection-vm-resistance-local-2026-11-15-f8586a1-32seed-10fixtures-summary.json)
and compressed [full report](protection-vm-resistance-local-2026-11-15-f8586a1-32seed-10fixtures.json.gz)
record this bounded automated evidence. Native ELF execution was unavailable
on the macOS ARM64 host, and the run does not substitute for independent human
adversarial review; the `published_resistance_results` criterion therefore
remains open. The earlier tamper result is explicitly retracted in the
[metric correction ledger](vm-resistance-metric-correction-2026-11-20.json).
The earlier [pre-change measurement](protection-vm-handler-diversity-local-2026-11-15-32seeds-summary.json)
remains as historical evidence.

A current-main local analyzer measurement on `f7246d5d` also completed the
`elf_vm_arith_x86_64` CodeVirtualization pair with IDA Pro 9.5, Ghidra 12.2,
radare2, angr, objdump, Unicorn, and the custom analyzer. IDA and Ghidra both
produced pseudocode for the protected fixture, and Unicorn observed exit code
45 for both original and protected binaries. Seven of nine expected analyzer
slots completed with zero tool errors; Binary Ninja remained unavailable due
to its license, and Triton was unavailable on the macOS ARM64 host. angr logged
an unhooked-address warning while its metric completed. This is one fixture
and one applied pass, so it adds current-source evidence without closing the
all-analyzer or resistance gates. The hash-bound [report summary](protection-adversarial-current-main-local-2026-11-15-f7246d5d-summary.json)
and its [raw report](protection-adversarial-current-main-local-2026-11-15-f7246d5d.json)
retain the exact measurements and limitations.

A repeat on `ec0cfa8e` built upstream Triton from source for the isolated
Python 3.13 environment and reran the same fixture/pass pair. Triton decoded
3,861 instructions in the protected binary and reported semantic support for
3,850; IDA Pro 9.5, Ghidra 12.2, angr, radare2, objdump, Unicorn, and the custom
analyzer also completed. Unicorn returned 45 for both binaries. Eight of nine
analyzer slots completed with zero tool errors. Binary Ninja remained
unavailable because its license was unavailable to the benchmark process.
The source report, fixture hash, and upstream Triton revision are pinned in
the [summary](protection-adversarial-current-main-local-2026-11-15-ec0cfa8e-summary.json)
and [raw report](protection-adversarial-current-main-local-2026-11-15-ec0cfa8e.json).
This is still one fixture and one applied pass; all-analyzer coverage and
generalized resistance remain open.

A fresh local run on current source `cbc61cef` applied CodeVirtualization to
the same `elf_vm_arith_x86_64` fixture. IDA Pro 9.5 and Ghidra 12.2 both
completed original/protected decompilation, and Unicorn observed exit code 45
for both binaries. Seven of nine analyzer slots completed without errors;
Binary Ninja was present but its license was unavailable, and Triton was not
installed. The report hash, fixture hash, tool outcomes, and limitations are
bound in the [summary](protection-adversarial-local-codevirtualization-2026-11-15-cbc61cef-summary.json)
and [raw report](protection-adversarial-local-codevirtualization-2026-11-15-cbc61cef.json).
This confirms the local IDA/Ghidra setup for one fixture and one pass, but does
not close all-analyzer coverage or establish generalized resistance.

The same current source ran all 22 named passes on that fixture. Two passes
applied and the other 20 were explicit no-ops; every pass row had 7/9 completed
analyzer slots, for 154/198 completed rows overall with zero missing or errored
rows. IDA Pro and Ghidra each completed all 22 pairs, and Unicorn returned 45
for every original/protected pair. Binary Ninja was unavailable because its
license was unavailable, Triton was not installed, and angr logged an
unhooked-address warning while completing its rows. The raw report and
hash-bound [summary](protection-adversarial-local-allpasses-2026-11-15-55369212-summary.json)
record the counts and scope. This remains one macOS fixture and does not close
all-analyzer coverage or generalized resistance.

The differential workflow [`43678223812`](https://github.com/seifreed/r2morph/actions/runs/43678223812)
produced two separately validated aggregate artifacts from source commit
`0e39d3ab`. Its five platform smoke reports cover 73 cases across ELF ARM32,
ELF ARM64, ELF x86-32, macOS ARM64, and Windows PE; every required case passed
with zero failures, errors, or skips. The hash-bound
[platform manifest](protection-platform-preview-run-2026-11-15-43678223812.json),
[platform summary](protection-platform-evidence-2026-11-15-43678223812.json),
and XML reports retain the results. The same run's VM semantic aggregate
passed 1,005 Linux ELF x86-64 fixtures over three seeds with zero QEMU
divergences, missing pairs, or unavailable pairs. Its hash-bound
[summary](protection-vm-semantic-native-parity-2026-11-15-43678223812-summary.json)
links the compressed full report. These bounded results add correctness
evidence, but do not prove general cross-platform parity or adversarial
resistance; both corresponding readiness criteria remain open.

Adversarial workflow shard 6 from run
[`43682458593`](https://github.com/seifreed/r2morph/actions/runs/43682458593)
completed on source `13ac8025` for `generated_signals_gcc-static-o2`, covering
all 22 passes and all nine expected analyzer slots. angr, Ghidra, objdump,
radare2, Triton, and the custom analyzer each completed 22 runs with no tool
errors or missing rows. Triton reached its configured instruction budget for
both original and protected measurements. Binary Ninja's module and IDA's
`idat` executable were unavailable, and Unicorn could not emulate an
instruction in this fixture. The hash-bound [shard summary](protection-adversarial-shard-2026-11-15-43682458593-06-summary.json)
and [raw report](protection-adversarial-shard-2026-11-15-43682458593-06.json)
retain these exact counts. This single-fixture shard adds Triton evidence but
does not close all-analyzer coverage or resistance.

The retained package includes 23 successfully completed shards from the same
32-shard workflow. Their reports cover 192 distinct fixtures and the same 22
passes: 38,016 analyzer rows were expected, 29,150 completed, 8,866 were
unavailable, and none were missing or errored. Binary Ninja and IDA Pro were
unavailable throughout this runner; Unicorn completed 3,806 rows and was
unavailable for 418 fixture rows.
The [partial-run summary](protection-adversarial-partial-run-2026-11-15-43682458593-summary.json)
binds each report hash and successful job to the compressed
[report bundle](protection-adversarial-partial-run-2026-11-15-43682458593.json.gz).
These bounded results leave complete analyzer coverage and generalized
resistance open.

The original run completed with 31 successful shards and one failed shard:
`OpaquePredicates` exceeded its 180-second worker budget on
`generated_cpp_exceptions_clangxx-static-o2`, causing the aggregate validator
to reject the run. A local profile attributed the dominant pass cost to
repeated register-alias construction in liveness analysis; commit `0e39d3ab`
caches those aliases and reduced the measured worker time from 22.405 to
10.151 seconds while producing byte-identical output. However, the failed
workflow source `13ac8025` already contains that optimization, so this timeout
shows the profile did not eliminate the CI failure. The profile is retained in
[the liveness report](profiling/2026-11-15-liveness-alias-cache.md). A full
repeat campaign with unchanged benchmark and runtime code, workflow
[`43691585628`](https://github.com/seifreed/r2morph/actions/runs/43691585628),
is in progress; it will test reproducibility, not validate the alias-cache
change. The 23-shard package above remains explicitly partial and does not
count the failed run as complete evidence.

The same C++ exception fixture was also transformed locally on the current
source commit with `OpaquePredicates` (13 mutations) and measured against all
nine analyzer slots. angr, radare2, objdump, and the custom analyzer completed
without tool errors; Binary Ninja, Unicorn, Triton, IDA Pro, and Ghidra were
unavailable on the macOS ARM64 host. The hash-bound [local report summary](protection-adversarial-local-opaque-2026-11-15-d8b9573c-summary.json)
links the raw [analyzer report](protection-adversarial-local-opaque-2026-11-15-d8b9573c.json).
This adds one applied-pass analyzer slice and leaves the all-analyzer criterion
open.

## Earlier full CI verification snapshots

At the time of this earlier snapshot, the latest completed GitHub CI run was
[`43680070257`](https://github.com/seifreed/r2morph/actions/runs/43680070257)
on source commit `13ac80258a5a51e0c872abe600bc04f52366ba0c`: all 15 jobs
passed, with zero failed or skipped jobs. It covered unit and integration
tests, installed-wheel and product smoke tests, property/fuzz validation,
lint, type checking, and Linux, macOS, and Windows on Python 3.12 and 3.13.
The later commit `68bb2d19` adds only published evidence, documentation, and a
regression test; `r2morph/`, `scripts/`, and workflow files are unchanged from
the CI-tested source. Its complete local suite passed on Python 3.14 with
6,895 passed, 225 skipped, and 82.16% coverage. GitHub CI and the differential
campaign for `68bb2d19` are still pending, so this does not claim those jobs
have validated that commit. The parity, analyzer-coverage, and resistance
criteria remain open.

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

The current-source VM resistance campaign on `7374619a` covered 10 ELF
fixtures and 32 seeds. Emulator-observed semantic parity was observed; tamper
divergence was not established because native execution was unavailable and
tampered exit codes were missing. Opcode, dispatcher, and bytecode grammar
diversity were observed, and progressive bytecode growth was supported on 7
fixtures. Each fixture's handler scan found four exact normalized cross-seed matches and zero
within-seed duplicates, so the zero cross-seed match criterion remains open.
Native ELF execution was unavailable on the macOS host, and independent human
adversarial review remains pending. The complete report and hashes are in the
[current VM summary](protection-vm-resistance-local-2026-11-15-32seed-10fixtures-summary.json)
and its compressed [campaign archive](protection-vm-resistance-local-2026-11-15-32seed-10fixtures.json.gz).
The prior source run remains available in
[`protection-vm-resistance-local-2026-11-14-32seed-10fixtures-summary.json`](protection-vm-resistance-local-2026-11-14-32seed-10fixtures-summary.json).

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
  The tamper-probe claims in this report are retracted because native execution
  was unavailable and all 160 tampered exit codes were missing; see the
  [correction ledger](vm-resistance-metric-correction-2026-11-20.json). Human
  review remains pending and general resistance remains unproven.

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

The continuous fuzz workflow completed on the current production-code tree in
[run 43559475263](https://github.com/seifreed/r2morph/actions/runs/43559475263),
using source commit `84e1202f09bb5265c3b8f8a4f5b21dd541901bfe`. Linux,
macOS ARM64, and Windows each built and installed the wheel and ran ten fuzz
targets for 5,000 cases per target (150,000 target runs total, zero failures).
All three reports counted 103 recoverable Mach-O parser warnings. Hash-bound
reports are listed in
[protection-fuzz-wheel-platform-2026-11-14-84e1202f.json](protection-fuzz-wheel-platform-2026-11-14-84e1202f.json).
This improves fuzz coverage evidence only; it leaves semantic parity and
adversarial resistance open.

The manually dispatched continuous-fuzz workflow then passed all three
platform jobs on source commit `350c0d79` in
[run 43631586471](https://github.com/seifreed/r2morph/actions/runs/43631586471).
Linux, macOS ARM64, and Windows each built and installed the wheel and completed
5,000 cases for all ten targets: 150,000 target runs total with zero failures.
Each runner recorded 103 recoverable Mach-O parser warnings. The report files
and their SHA-256 digests are
[bound in this summary](protection-fuzz-continuous-run-2026-11-14-43631586471.json).
The fuzzed runtime and campaign inputs are unchanged through the current main
tree; later commits only published evidence and added tests. This is fuzzing
evidence, not proof of semantic equivalence or platform parity.

A local source-tree campaign at commit `1946be26` exercised the real
`CodeVirtualization` pass on fixture `elf_vm_arith_x86_64`. One function was
fully virtualized; IDA Pro 9.5 completed both sides and reported 26 additional
decompiler lines and 939 additional bytes for the protected binary. The same
run explicitly records Binary Ninja as unavailable due to license status and
Ghidra/Triton as unavailable on the host. Its raw report and hash-bound summary
are
[protection-adversarial-local-ida-2026-11-14-1946be26.json](protection-adversarial-local-ida-2026-11-14-1946be26.json)
and
[protection-adversarial-local-ida-2026-11-14-1946be26-summary.json](protection-adversarial-local-ida-2026-11-14-1946be26-summary.json).
This is one fixture and one pass; it does not close the named-analyzer matrix
or establish general resistance.

A follow-up local source-tree run at `87af8f71` evaluated all 22 declared
passes on that fixture with IDA Pro 9.5, Ghidra 12.2, and a local build of
Triton from upstream source commit `0ff0315021c416995e169334b25eb84f818caaeb`.
Only CodeVirtualization and InstructionSubstitution applied; the other 20
passes were explicit no-ops on this input. For CodeVirtualization, IDA reported
+26 decompiler lines and +939 bytes; Ghidra reported +35 lines and +607 bytes.
Triton processed the protected image with 3,861 decoded instructions, 3,850
semantically supported instructions, 29 invalid bytes, and no exhausted
instruction budget. One function was fully virtualized with no partial or
unsupported functions. Across the 198 expected pass/analyzer rows, 176
completed without errors; Binary Ninja's API explicitly rejected the local
license for all 22 passes. The raw report and its hash-bound summary are
[protection-adversarial-local-multianalyzer-2026-11-14-87af8f71.json](protection-adversarial-local-multianalyzer-2026-11-14-87af8f71.json)
and
[protection-adversarial-local-multianalyzer-2026-11-14-87af8f71-summary.json](protection-adversarial-local-multianalyzer-2026-11-14-87af8f71-summary.json).
This is still one fixture, and 20 passes did not apply; the all-analyzer and
generalized-resistance criteria remain open.

A follow-up local source-tree campaign at commit `f1fec959` measured the same
22 passes on both `elf_vm_arith_x86_64` and `elf_x86_64`. CodeVirtualization
and InstructionSubstitution applied to both samples; the other 20 passes were
no-ops on both. All 44 IDA Pro, Ghidra, Triton, angr, radare2, objdump, Unicorn,
and custom analyzer rows completed without errors. Binary Ninja's 44 rows are
explicitly unavailable because the local license was unavailable, giving 352
completed and 44 unavailable rows out of 396. Fixture hashes, per-pass states,
analyzer coverage, and the raw-report hash are recorded in the
[summary](protection-adversarial-local-multianalyzer-two-fixture-2026-11-14-f1fec959-summary.json)
and [raw report](protection-adversarial-local-multianalyzer-two-fixture-2026-11-14-f1fec959.json).
This remains a two-fixture local calibration; 20 passes did not apply, and the
all-analyzer and generalized-resistance criteria remain open.

The adversarial workflow on source commit `334f6626` completed all 32 fixture
shards. It covered 362 samples, including 200 generated fixtures, across 22
passes: 7,964 pass rows and 71,676 expected analyzer rows. It recorded 55,220
completed analyzer rows (77.04%), 16,456 unavailable rows, and zero tool
errors. Binary Ninja and IDA Pro were unavailable for all rows in that Linux
workflow; Unicorn lacked support for an instruction in 528 rows. The
CodeVirtualization pass applied to all 362 samples and virtualized 636
functions, while 14 functions were rejected for exception/unwind or SSA
liveness capability gaps. The 44.8 MB raw report is retained compressed with
hashes in
[the run summary](protection-adversarial-run-2026-11-14-43592902305.json) and
[the report archive](protection-adversarial-corpus-2026-11-14-43592902305.json.gz).

The same workflow's VM resistance smoke preserved semantic parity across 15
fixtures and 10 seeds, observed cross-fixture and seed diversity, and had all
tested tamper probes diverge. Progressive bytecode growth was supported on 6
of 15 fixtures; normalized output still had 401 above-threshold similarities
among 2,295 seed comparisons. The hash-bound reports are
[summarized here](protection-vm-resistance-run-2026-11-14-43592902305.json).
Their evidence quality is automated smoke, and human adversarial review
remains pending.

A separate local run on source commit `8ab01d2f` applied CodeVirtualization to
one fixture. IDA Pro 9.5 and Ghidra 12.2 both completed; IDA reported +1
function, +26 decompiler lines, and +939 bytes, while Ghidra reported +2
functions, +35 lines, and +607 bytes. Binary Ninja remained unavailable
because its license was unavailable, and Triton was unavailable on macOS
ARM64. The raw report and hash-bound
[summary](protection-adversarial-local-analyzer-2026-11-14-8ab01d2f-summary.json)
are retained. This adds a current local IDA/Ghidra slice but does not close the
all-analyzer or general resistance criteria.

A local all-pass run on source commit `fadc0e63` covered shard 0/32: four
repository ELF x86-64 fixtures across all 22 passes, producing 88 pass rows
and 792 expected analyzer rows. IDA Pro 9.5 and Ghidra 12.2 completed all 88
rows; the other available local analyzers completed as well, for 616 total
completions and zero tool errors. Binary Ninja and Triton were unavailable
for all 88 rows each. Ten transformations applied, with zero pass errors;
the remaining 78 no-op rows are retained rather than counted as coverage
gaps. This is a bounded local analyzer shard and leaves both all-analyzer
coverage and general resistance open. Its compressed report and manifest are
[here](protection-adversarial-local-allpasses-shard-2026-11-14-fadc0e63.json.gz)
and [here](protection-adversarial-local-allpasses-shard-2026-11-14-fadc0e63-summary.json).

A second local shard at source commit `2237bacc` adds four distinct fixtures
across the same 22 passes. The two shards now cover eight fixtures, 176 pass
rows, and 1,584 expected analyzer rows; 1,232 completed with zero tool errors.
IDA Pro and Ghidra completed all 176 rows each. Binary Ninja and Triton remain
unavailable for 176 rows each. Eighteen transformations applied and the other
158 rows are explicit no-ops. The combined manifest binds each report to its
own source commit and fixture hashes:
[summary](protection-adversarial-local-allpasses-shards-2026-11-14-2237bacc-summary.json).
This expands bounded local coverage but leaves both release criteria open.

A third shard at source commit `654dc023` adds four more distinct fixtures.
Across 12 fixtures, the local campaign records 264 pass rows and 2,376
expected analyzer rows; 1,848 completed and 528 are unavailable because
Binary Ninja lacks a local license and Triton is unavailable on macOS ARM64.
IDA Pro and Ghidra each completed all 264 rows. Twenty-four transformations
applied, 240 rows were explicit no-ops, and no pass or adapter errors were
reported. angr emitted unsupported-dirty-helper and unhooked-address warnings
during this shard; the report preserves its completed status and the warning
is recorded as a limitation. The three-shard manifest binds reports to source
commits and fixture hashes:
[summary](protection-adversarial-local-allpasses-shards-2026-11-14-654dc023-summary.json).
This evidence remains a bounded local sample and does not close analyzer
coverage, differential correctness, or resistance criteria.

The fourth local shard at source commit `14df3fb4` covers four additional
repository fixtures across the same 22 passes, adding 88 pass rows and 792
expected analyzer slots. IDA Pro completed all 88 rows; six analyzers completed
528 rows total with zero adapter or pass errors. Binary Ninja was unavailable
because its license was unavailable, Ghidra's headless executable was not
installed, and Triton was unavailable. Eight pass rows applied and the other
80 were explicit no-ops. angr emitted unsupported-dirty-helper and
unhooked-address diagnostics, which remain a limitation. The report and
hash-bound manifest are
[here](protection-adversarial-local-allpasses-shard-2026-11-14-14df3fb4.json.gz)
and
[here](protection-adversarial-local-allpasses-shard-2026-11-14-14df3fb4-summary.json).
This bounded shard adds IDA coverage but leaves the all-analyzer criterion
open.

A follow-up run of the same deterministic shard on source commit `3af283d8`
configured both IDA Pro and Ghidra headless explicitly. Across the same four
fixtures and 22 passes, it completed 616/792 analyzer rows with zero tool or
pass errors and zero missing rows. IDA Pro and Ghidra each completed all 88
rows; Binary Ninja remained unavailable because its local license was not
available, and Triton was unavailable on macOS ARM64. Eight pass rows applied
and 80 were no-ops. angr again reported unsupported dirty helpers and an
unhooked address. The bounded, hash-bound artifact is recorded in the
[shard summary](protection-adversarial-local-allpasses-shard-2026-11-14-3af283d8-summary.json)
and its compressed report. This closes the missing Ghidra evidence for this
shard only; all-analyzer coverage and generalized resistance remain open.

The complete Linux all-pass workflow run on source commit `fadc0e63` finished
successfully with all 33 jobs, including all 32 shards and the aggregate. Across
362 samples and 22 passes, it recorded 7,964/7,964 expected pass rows and
71,676 analyzer slots: 55,220 completed (77.04%), 16,456 unavailable, and zero
missing or errored tool rows. Binary Ninja and IDA Pro were unavailable for all
pass rows, while Unicorn lacked support for an instruction in 528 rows. The
CodeVirtualization pass applied to all 362 samples and virtualized 636
functions; 14 additional functions remained unsupported for exception/unwind
or SSA liveness capability gaps. The full reports are retained in the
[hash-bound run summary](protection-adversarial-run-2026-11-14-43615553431.json),
[corpus archive](protection-adversarial-corpus-2026-11-14-43615553431.json.gz),
and [maturity archive](protection-adversarial-maturity-2026-11-14-43615553431.json.gz).
The run is bounded evidence and leaves all-analyzer coverage open.

The same run's VM resistance smoke preserved semantic parity across 15 fixtures
and 10 seeds. It observed opcode assignment, handler, dispatcher, and bytecode
grammar diversity; all tested tamper probes diverged, and progressive bytecode
growth was supported on 6 fixtures. This remains automated smoke evidence, with
human adversarial review pending. Its reports and SHA-256 digests are retained
in the [VM evidence summary](protection-vm-resistance-run-2026-11-14-43615553431.json)
and linked archives. The result does not establish generalized resistance and
the release criterion remains open.

A fresh local all-pass shard on source commit `ae2bf209` covered four repository ELF fixtures across all 22 passes. The run recorded 88/88 pass rows and 792 expected analyzer slots: 704 completed, 88 unavailable, and zero tool or pass errors. IDA Pro, Ghidra, angr, radare2, objdump, Unicorn, Triton, and the custom analyzer completed all 88 slots each. Binary Ninja was unavailable for all 88 slots because its license was not available to the process. Eight pass rows applied and 80 were explicit no-ops. Fixture hashes, tool outcomes, and the raw report digest are bound in the [summary](protection-adversarial-local-allpasses-shard-2026-11-16-ae2bf209-summary.json) and its compressed [report](protection-adversarial-local-allpasses-shard-2026-11-16-ae2bf209.json.gz). This adds current-source IDA coverage on four fixtures; it does not close all-analyzer coverage or establish generalized resistance.

## Adversarial analyzer campaign — 2026-11-16 (run 43952405619)

The `Adversarial Analysis Benchmark` workflow completed all 33 jobs on source
commit `6c60d58d186fc7725465313b79ce488dee1ee0c4`. It covered 362 samples and
22 passes, observed all 7,964 expected pass rows and all 71,676 expected analyzer
rows, and reported zero missing rows or execution errors. Of the analyzer rows,
55,220 completed (77.04%) and 16,456 were unavailable: Binary Ninja was absent
for 7,964 rows, IDA Pro's `idat` executable was absent for 7,964 rows, and
Unicorn did not support the fixture instruction in 528 rows. The workflow also
reported 17 bounded evidence blockers, including three unavailable `angr`
decompiler baseline pairs.

The hash-bound [manifest](protection-adversarial-run-2026-11-16-43952405619.json)
and [compressed raw report](protection-adversarial-run-2026-11-16-43952405619.json.gz)
are covered by a regression test. The attached VM smoke artifacts are byte for
byte identical to run `43800549091`; automated smoke remains complete, but the
human adversarial review is pending and generalized resistance is unproven.
Neither the all-named-analyzers gate nor the resistance release criterion closes.

## Current-source local IDA shards — 2026-11-17

On source commit `dedfef14f00bda1e8f90bae6759c7b55899c8b3d`, local adversarial
shards 0 and 1 covered 8 distinct repository ELF x86-64 fixtures across all
22 passes: 176/176 pass rows and 1,584/1,584 analyzer slots were present, with
zero missing rows or errors. IDA Pro 9.5 completed 176/176 rows. Overall,
1,056 analyzer rows completed and 528 were unavailable (Binary Ninja, Ghidra,
and Triton, 176 each). Generated Linux fixtures were not included because the
Darwin ARM64 host lacks their Linux x86-64 toolchain. The raw reports, fixture
hashes, and exact per-shard counts are in the
[compatibility corpus record](compatibility-corpus.md#current-source-local-ida-shards),
with regression checks in
[test_published_local_ida_adversarial_shards_dedfef14.py](../tests/unit/test_published_local_ida_adversarial_shards_dedfef14.py).
This adds bounded current-source IDA coverage; the all-analyzer, cross-platform
parity, and general resistance criteria remain open.

## Current-source local Ghidra virtualization shard — 2026-11-17

On source commit `8a612589dab88d4c928ea46ab8c525c305ef9184`, the Darwin ARM64
runner measured `CodeVirtualization` on four repository ELF x86-64 fixtures.
All four pass rows and all 36 expected analyzer rows were present. Ghidra 11.4.2
completed 4/4 rows. In total, 24/36 analyzer rows completed (66.67%), eight
were unavailable (Binary Ninja and Triton), four IDA Pro rows timed out, and no
rows were missing. No generated Linux fixtures were included. Ghidra reported
five additional functions, five additional decompiler entrypoints, 74
additional decompiler lines, and 1,059 additional decompiler bytes. These
measurements are diagnostic and do not establish generalized resistance or
cross-platform parity. See the hash-bound
[summary](protection-adversarial-local-ghidra-virtualization-2026-11-17-8a612589-summary.json),
[compressed report](protection-adversarial-local-ghidra-virtualization-2026-11-17-8a612589.json.gz),
and [regression test](../tests/unit/test_published_local_ghidra_virtualization_8a612589.py).
All-analyzer, cross-platform parity, and published resistance criteria remain
open.

## Published differential workflow corpus — 2026-11-17

Workflow [44043963389](https://github.com/seifreed/r2morph/actions/runs/44043963389)
completed on source commit `8a612589dab88d4c928ea46ab8c525c305ef9184`: 360
public Linux ELF x86-64 builds, six passes, and 19,440/19,440 differential
inputs passed. It applied 713 transformations and omitted 1,447 ineligible
rows; no static-recovery measurement failed. Optional decompiler runners were
omitted, so this does not close the analyzer gate. Five platform slices
completed 76 selected smoke cases without errors or failures; the limited
selection does not establish full cross-platform parity. See the hash-bound
[summary](protection-adversarial-workflow-evidence-2026-11-17-44043963389-summary.json),
[curated raw reports](protection-adversarial-workflow-evidence-2026-11-17-44043963389.tar.gz),
and [regression test](../tests/unit/test_published_workflow_evidence_44043963389.py).
Analyzer, parity, and published resistance criteria remain open.

## Published differential workflow corpus — 2026-11-18

Workflow [44213229027](https://github.com/seifreed/r2morph/actions/runs/44213229027)
completed all 85 jobs successfully on source commit
`1cf52005310a527b86c68b4ff713ce248f1432d7`. Its artifacts report 5,540 core
differential classifications and 7,572 extended-maturity classifications with
zero failed seeds or errors; 2,450 VM-semantic tests and 1,288 composition
tests also completed without failures. Differential fuzzing covered 1,728
cases with no failures. Cross-format smoke recorded 2,146 tests, of which 290
were skipped and are not counted as passes. These CI artifacts are bounded
evidence, not a complete compatibility or resistance proof. Binary Ninja is
unavailable because no valid license is available, so the named-analyzer gate
remains open. The current-run aggregate and limits are recorded in
[the evidence summary](differential-run-2026-11-18-44213229027-summary.json).

## Current-main validation — 2026-11-18

On source commit `0491ba06a09240eee7b36241cc4d8e4b040a7a83`, the differential
workflow completed all 85 jobs. Its 10-pass core campaign recorded 10,860
classified runs with complete evidence and zero failures or errors; the
12-pass extended campaign recorded 13,032 with the same result. The continuous
fuzz workflow completed 150,000 target runs across Ubuntu, Windows, and macOS
with zero failures. The local current-source fuzz campaign separately ran
50,000 target cases on macOS ARM64 with zero failures and 106 retained Mach-O
parser warnings.

The 33-job adversarial workflow completed 362 fixtures (200 generated), 22
passes, and all 71,676 analyzer slots. It completed 55,220 (77.04%), with
16,456 explicitly unavailable, no errors, and no missing rows. Binary Ninja
and IDA Pro were unavailable for every row; Unicorn lacked support for 528
rows. Fourteen virtualization functions were reported unsupported. These are
bounded results and do not establish generalized resistance or all-analyzer
coverage. The exact counters, workflow links, artifact hashes, and limitations
are pinned in [the current-main validation manifest](current-main-validation-2026-11-18-0491ba06.json)
and its [local fuzz manifest](continuous-fuzz-local-2026-11-18-0491ba06.json).

The main CI run for this source passed 11 jobs but ended cancelled while the
four macOS jobs were in `Run cross-platform package smoke tests`; their results
remain unverified. The separate automated independent-review workflow passed
28 checks, but recorded `human_signoff: not-attested` and
`release_decision: block-vm-milestone`. All three 1.0 blockers remain open.

The next main commit, `e8f60760fc9c132269d7a0dd11b5568d1bfc5db8`, passed 11 CI
jobs, including unit/integration tests, lint, typecheck, installed-wheel, and
Windows/Linux checks. Four macOS jobs were cancelled during cross-platform
package smoke and remain unverified. Differential workflow
[`44308008537`](https://github.com/seifreed/r2morph/actions/runs/44308008537)
ran all shards but failed its aggregate because fixtures appeared in multiple
shards for the same seed; the duplicate rows had matching input and output
hashes. The root cause was size-weighted shard assignment over generated
binaries built independently by each worker. Sharding now uses sorted unique
fixture names and balances fixture counts, independent of compiled sizes. A
new workflow run is required to verify the correction. Runtime skew between
shards remains unmeasured, so all release criteria stay open.

## Current-source local all-pass analyzer shard — 2026-11-18

On source commit `9112e77fd749b9ee24b7879012a76dda15233ee8`, a Darwin ARM64
runner measured all 22 configured mutation passes across four repository ELF
x86-64 fixtures (shard 0 of 32). All 88 pass rows and 792 expected analyzer
slots were present; 528 slots completed across angr, IDA Pro, objdump, radare2,
Unicorn, and the custom analyzer, with zero pass/analyzer errors or missing
rows. Binary Ninja, Ghidra, and Triton were unavailable for all 88 rows each.
angr emitted unsupported VEX-operation and CCall diagnostics; those rows are
accounted as completed, but their decompiler metrics have this limitation. The
Linux generated-fixture corpus was not included on the macOS host. This report
is bounded analyzer-output evidence and does not establish generalized
resistance. See the hash-bound [summary](protection-adversarial-current-main-2026-11-18-9112e77f-shard-0-summary.json),
[compressed report](protection-adversarial-current-main-2026-11-18-9112e77f-shard-0.json.gz),
and [regression tests](../tests/unit/test_published_current_main_adversarial_shard_9112e77f.py).
The analyzer and published-resistance gates remain open.

On source commit `7cb29ce109d1334577b2cf20cdb2375421a55224`, a second Darwin
ARM64 shard measured four more repository ELF x86-64 fixtures and all 22 passes.
All 88 pass rows and 792 analyzer slots were present; 528 completed across
angr, IDA Pro, objdump, radare2, Unicorn, and the custom analyzer, with zero
pass/analyzer errors or missing rows. Eight passes applied. Binary Ninja,
Ghidra, and Triton were unavailable for all 88 rows each. This partial shard
does not complete the 32-shard corpus or demonstrate generalized resistance.
See its hash-bound [summary](protection-adversarial-current-main-2026-11-18-7cb29ce1-shard-1-summary.json),
[compressed report](protection-adversarial-current-main-2026-11-18-7cb29ce1-shard-1.json.gz),
and [regression test](../tests/unit/test_published_current_main_adversarial_shard_7cb29ce1.py).
Both related release gates remain open.

## Current-main handler-template diversity measurement — 2026-11-19

On production source commit `5b7b566a0a39e4012decf2010f7b9914ada84139`, a
local run of `scripts/protection_handler_clustering.py` measured 100 seeds and
255 generated interpreter handlers per seed. All opcode assignments were
unique and no single seed had duplicate normalized handlers. Across seeds,
the report found 38 exact normalized handler matches in 19 two-handler
clusters. This generator-template measurement does not execute protected
binaries, measure analyst attack cost, or establish resistance. The raw report,
hash-bound summary, and pinned regression test are
[`protection-vm-handler-diversity-local-2026-11-19-5b7b566a-100seeds.json`](protection-vm-handler-diversity-local-2026-11-19-5b7b566a-100seeds.json),
[`summary`](protection-vm-handler-diversity-local-2026-11-19-5b7b566a-100seeds-summary.json),
and
[`test_published_vm_handler_diversity_100seeds_5b7b566a.py`](../tests/unit/test_published_vm_handler_diversity_100seeds_5b7b566a.py).
The zero-collision and published-resistance criteria remain open.

## Current-main three-platform continuous fuzz run — 2026-11-19

Continuous Fuzzing workflow
[`44613330309`](https://github.com/seifreed/r2morph/actions/runs/44613330309)
passed on source commit `b561237880a5b42bd45494424fbd291ae832dfc7`. Ubuntu,
macOS 15, and Windows each ran 5,000 deterministic inputs against the same
ten parser, assembler, VM, relocation, and binary-rewriter targets: 150,000
target runs total and zero failures. All three reports recorded 101
recoverable `macho_load_commands.warning` diagnostics. The
[hash-bound summary](continuous-fuzz-2026-11-19-44613330309-summary.json),
the three compressed reports, and the
[regression contract](../tests/unit/test_published_continuous_fuzz_44613330309.py)
pin the run and its scope. This bounded harness run does not establish
arbitrary-input semantic equivalence, full platform parity, or adversarial
resistance.

## Current-source release-contract check — 2026-11-24

On source commit `492794568cc00afd8aec11630b3979014086d514`,
`scripts/check_release_contract.py` passed for `0.4.0-alpha.3`, and all 158
release-contract/readiness tests passed on Python 3.13.17/macOS arm64 with
angr 10.0.7 and Keystone 0.9.2 available. This confirms the alpha metadata and
that the one-zero gate still blocks the open analyzer, cross-platform parity,
and published-resistance criteria. It does not validate a release build, wheel,
provenance, or publication. The result and scope limits are pinned in
[`release-contract-check-local-2026-11-24-49279456.json`](release-contract-check-local-2026-11-24-49279456.json).

## Current-source local continuous fuzz — 2026-11-24

On source commit `92ff809ca8eecf9705189bb9728539365770d32b`, a macOS ARM64
host running Python 3.13.17 completed 5,000 deterministic cases for each of
the ten continuous-fuzz targets (50,000 target runs total) with zero failures.
The parser recorded 107 recoverable `macho_load_commands.warning` diagnostics.
The run covers bounded parser, assembler, VM, relocation, and binary-rewriter
inputs; it does not establish transformed-program equivalence, exhaustive fuzz
coverage, full platform parity, or adversarial resistance. Its command,
environment, source hash, report hash, and limits are pinned in the
[summary](continuous-fuzz-local-2026-11-24-92ff809c.json), the
[raw report](continuous-fuzz-local-2026-11-24-92ff809c-report.json), and the
[regression test](../tests/unit/test_published_continuous_fuzz_local_92ff809c.py).

## Current-source three-platform continuous fuzz — 2026-11-24

Continuous Fuzzing workflow
[`45460386121`](https://github.com/seifreed/r2morph/actions/runs/45460386121)
passed on source commit `92ff809ca8eecf9705189bb9728539365770d32b`. Ubuntu,
Windows, and macOS 15 each completed 5,000 deterministic inputs for all ten
parser, assembler, VM, relocation, and binary-rewriter targets (50,000 target
runs per platform; 150,000 total), with zero failures and 103 recoverable
`macho_load_commands.warning` diagnostics per platform. The source script hash,
raw report hashes, artifact IDs and ZIP digests, and limits are pinned in the
[campaign summary](continuous-fuzz-2026-11-24-45460386121-summary.json), the
three platform reports, and the
[regression test](../tests/unit/test_published_continuous_fuzz_45460386121.py).
This bounded harness does not establish semantic equivalence for arbitrary
transformed binaries, exhaustive fuzz coverage, full platform parity, or
adversarial resistance.

## Current-source three-platform continuous fuzz — 2026-11-25

Continuous Fuzzing workflow
[`45581219724`](https://github.com/seifreed/r2morph/actions/runs/45581219724)
passed on source commit `c1d7f7299e36c994aa32fb4a73fbdda7a81996c6`. Ubuntu,
macOS 15, and Windows each built and installed the wheel, then completed 5,000
cases for each of ten parser, assembler, VM, relocation, and binary-rewriter
targets: 150,000 target runs total, with zero failures and 103 recoverable
`macho_load_commands.warning` diagnostics on each platform. The commit's CI
also passed the Hypothesis property test for overlapping relocation mappings
on Ubuntu. A follow-up workflow
[`45583595035`](https://github.com/seifreed/r2morph/actions/runs/45583595035)
on source `300194fa9a4ff5cade7e32535d9137ad7ab99ffe` then passed the same two
property test items on all three runners. Its [summary](continuous-fuzz-relocation-property-2026-11-25-45583595035-summary.json)
and [regression test](../tests/unit/test_published_relocation_property_cross_platform_45583595035.py)
pin each runner result and artifact. This adds evidence for relocation mapping
only; complete pass-by-platform parity remains open.
The source script hash, report hashes, artifact IDs and ZIP digests, seed, and
limits are pinned in the [summary](continuous-fuzz-2026-11-25-45581219724-summary.json),
three platform reports, and
[regression test](../tests/unit/test_published_continuous_fuzz_45581219724.py).
This bounded campaign does not establish arbitrary transformed-program
equivalence, exhaustive fuzz coverage, full product parity, or adversarial
resistance.

## Current-source local IDA analyzer sample — 2026-11-25

On source `6756d0b636ac3a64b4a96564c2671c1182f1acd2`, the local adversarial
benchmark applied `CodeVirtualization` to `elf_vm_arith_x86_64` and measured all
nine analyzer slots. IDA Pro 9.5 completed analysis and decompilation on both
files: function count changed 1→2, pseudocode changed 4→30 lines, and neither
decompilation reported errors. `angr`, `custom`, `objdump`, radare2, and Unicorn
also completed. Binary Ninja was unavailable because no valid license is
installed; Triton and Ghidra were unavailable in this environment. The sample
uses one fixture and one pass, so it does not measure generalized resistance or
close the all-analyzer or published-resistance gates. The [manifest](protection-adversarial-current-source-ida-one-fixture-2026-11-25-summary.json),
[raw report](protection-adversarial-current-source-ida-one-fixture-2026-11-25.json),
and [regression test](../tests/unit/test_published_adversarial_current_source_ida_one_fixture_2026_11_25.py)
bind its scope, hashes, and unavailable analyzers.

### Current-source IDA MCP spot check — 2026-11-25

On source `9c9177952decf745674715563fbfa8e73a92a090`,
`CodeVirtualization` applied to one function in the same ELF fixture. Unicorn
returned exit code 45 for both original and protected binaries. IDA/Hex-Rays
through the local MCP completed analysis and decompilation for both; IDA found
one function in the original and two in the protected sample. The local CLI
benchmark still reports IDA unavailable because `idat` is not installed, so
the MCP measurements are supplemental and do not fill the complete analyzer
matrix. Binary Ninja had no valid license; Triton, angr, and the Ghidra CLI were
unavailable. The hash-bound [summary](protection-adversarial-current-source-ida-one-fixture-2026-11-25-9c917.json),
[raw CLI report](protection-adversarial-local-current-9c917.json.gz), and
[regression test](../tests/unit/test_published_current_source_ida_one_fixture_9c917.py)
pin the source, binary hashes, outcomes, and limits. One fixture/pass does not
establish analyzer coverage or generalized resistance.

## Blocker index

### Linux timeout integration fixture — 2026-11-18

The full Ubuntu 26.04 / Python 3.12 integration run at source `812046fe`
completed with 1,313 passed, 174 skipped, and one failure:
`test_validator_timeout_path`. Ubuntu's `/bin/sleep` is a multicall executable
that selects its applet using `argv[0]`; the test had copied it under the
different names `sleep_original` and `sleep_mutated`, so both executions failed
before reaching the timeout and emitted different applet errors. The test now
keeps the `sleep` basename in separate directories and asserts both processes
actually time out. The existing Linux CI run also had a separate VM varargs ABI
failure; the same integration test passed in the full local run. Re-run CI is
required to verify the fixture correction and determine whether the VM failure
persists. Related analyzer, VM resistance, human signoff, and stable-release
gates remain open.

The timeout fixture now uses identical generated shell scripts instead of
copies of `/bin/sleep`. Local macOS execution showed that copying the signed
system utility is terminated immediately with signal 9, which made the Linux
multicall fix fail outside Linux. The generated fixture uses the process
adapter's shebang path and exercises the actual timeout on both systems.

CI run [`44387590551`](https://github.com/seifreed/r2morph/actions/runs/44387590551)
confirmed the timeout fix, but again failed the floating-point varargs ABI test
on the native Linux runner. The same 98-case smoke passed twice locally against
both the checkout and an installed wheel in an x86-64 emulated Linux
environment; ten additional fixture runs produced the same mutated-binary hash
and exit code 73. The regression assertion now includes both program return
codes and captured outputs so the next native run exposes the mismatch. The
cause remains open; do not treat the local emulation as native-host evidence.

### Floating-point varargs virtualized-entry failure — 2026-11-19

Commit `5519152b` changed the direct-call target decoder from `eax` to `r10d`
to preserve System V `al`. That register-level invariant is still covered by a
unit test, but it did not resolve the native Linux integration failure: run
`44425946694` on Ubuntu 26.04 / Python 3.12 returned `-11` for the mutated
floating-point varargs fixture while the original returned `73`. The fixture's
stats show that the variadic callee was virtualized and the caller was skipped,
so this failure is on the virtualized variadic-entry path, not evidence about a
virtualized outgoing native call. A GCC 15 build of equivalent C source passes
in a local x86-64 emulated Debian container across 12 `PYTHONHASHSEED` values;
this does not reproduce the native runner failure and is not sufficient to
close it.

The integration assertion attempts to run GDB after a signal termination and
captures a bounded backtrace, `RIP`/`RSP`/`RAX`, and nearby instructions, with
the generated binary path redacted. GDB in the local Docker environment is
blocked from reading registers by the container's ptrace restrictions. The
exact floating-point varargs regression subsequently passed in the full
Linux/Python 3.12 integration suite in CI run
[`45586185240`](https://github.com/seifreed/r2morph/actions/runs/45586185240),
on source `c51e6426e49f9db932025f9a458a1348c37b493e`; the job log records
`test_virtualized_elf_preserves_floating_point_varargs_register_and_stack_abi`
as passed. This closes that reproduced fixture failure. General varargs/ABI
parity and the broader release gates remain open.

The cross-platform installed-wheel smoke was reproduced on macOS ARM64 from
source `d57368bd`: all 679 selected tests passed under Python 3.12.16 in 14.18
seconds and Python 3.13.18 in 13.65 seconds. In GitHub run
[`44387590551`](https://github.com/seifreed/r2morph/actions/runs/44387590551),
the four corresponding macOS jobs have remained in that step for over 30
minutes. The smoke now requests Python thread dumps after 60 seconds and bounds
its pytest subprocess to five minutes while retaining the complete test target
list. The runner-specific hang and full GitHub matrix result remain unverified.

The published `v0.4.0-alpha.3` release pipeline completed all five jobs,
including installed-wheel tests, PyPI publication, provenance attestation, and
GitHub release creation. The release contains the wheel, source archive, SBOM,
and SHA-256 checksums. The pinned run record is
[release-pipeline-2026-09-07.json](release-pipeline-2026-09-07.json), with the
[workflow run](https://github.com/seifreed/r2morph/actions/runs/34096579308)
and [published release](https://github.com/seifreed/r2morph/releases/tag/v0.4.0-alpha.3).
This verifies the alpha release path only; `one-zero-readiness.json` continues
to block stable-major publication until every 1.0 evidence criterion is complete.

## Current-source differential and compatibility campaign — 2026-11-25

Workflow [`45602419475`](https://github.com/seifreed/r2morph/actions/runs/45602419475)
passed all 86 jobs on source `9c9177952decf745674715563fbfa8e73a92a090`.
The Linux ELF x86-64 core matrix recorded 10,860 classifications across ten
passes (3,480 applied, 7,380 omitted); the extended matrix recorded 13,032
across twelve passes (3,406 applied, 9,626 omitted). All rows had complete
evidence, with zero transformation errors or semantic failures. The campaign
also passed 2,208 composition cases, 370 compatibility samples across GCC,
Clang, C/C++, five optimization levels, PIE/stripped and static/dynamic
variants, 2,220 radare2 static-recovery measurements, and 1,005 VM/QEMU
comparisons. Six bounded platform previews passed 78 cases. The
[hash-bound manifest](differential-run-2026-11-25-45602419475.json),
[compressed reports](differential-corpus-merged-45602419475.json.gz),
[extended report](extended-maturity-merged-45602419475.json.gz),
[public corpus report](public-compatibility-merged-45602419475.json.gz),
[VM report](vm-semantic-campaign-45602419475.json.gz), and
[platform summary](platform-evidence-45602419475.json) preserve the evidence.

This establishes correctness only for the measured corpora and selected
pass/platform combinations. Omitted transformations are not successful
transformations; optional decompiler runners are absent from the public corpus
workflow; 22 decompiler maturity blockers remain. Full cross-platform parity,
all-named-analyzer coverage, and generalized VM resistance remain open.

| ID | Area | Evidence |
|---|---|---|
| RB-001 | per-pass maturity | `support-matrix.json` `pass-maturity.md` |
| RB-002 | differential evidence | `compatibility-corpus.md` `differential-corpus.yml` |
| RB-003 | VM semantics | `support-matrix.json` `independent-review-packet.md` |
| RB-004 | cross-platform parity | `support-matrix.json` `pass-maturity.md` |
| RB-005 | adversarial benchmark | `compatibility-corpus.md` `adversarial-benchmark.yml` |
| RB-006 | VM resistance | `protection-handler-clustering.json` `protection-bytecode-grammar.json` |
| RB-007 | human VM signoff | `independent-review.json` `independent-review-packet.md` |
