# Compatibility Corpus

The public, reproducible corpus is maintained in
[`seifreed/r2morph-corpus`](https://github.com/seifreed/r2morph-corpus), currently
pinned to commit
[`5f16a6fdcccbe2c3c97100f339a68ab916ca2e19`](https://github.com/seifreed/r2morph-corpus/commit/5f16a6fdcccbe2c3c97100f339a68ab916ca2e19).
It contains source programs, the build matrix, SHA-256 manifests, differential
execution records, and static-recovery benchmark results. The project
repository does not embed generated binaries.

The scheduled `public-compatibility-corpus` job checks out that immutable commit,
builds its full GCC/Clang matrix, then selects a deterministic bounded matrix
with five variants per source/compiler: `O0` and `O1` non-PIE with symbols and
dynamic linking, `O2` PIE stripped, `O3` non-PIE static, and `Os` non-PIE with
symbols and dynamic linking when the linker is available. The selected records
are split across four parallel shards. Each shard transforms its complete
record subset with the six selected passes, compares the original and
transformed process observables, and runs the radare2 static-recovery
benchmark. An aggregate job validates that the shard artifacts form one
complete, duplicate-free matrix before publishing the bounded evidence. This is additional
continuous Linux ELF x86-64 corpus evidence; it does not claim PE, Mach-O, ARM,
or AArch64 parity.
The differential workflow also aggregates the independent PE, Mach-O ARM64,
native ELF ARM64, native ELF ARM32, and native ELF x86 32-bit JUnit artifacts into
`differential-platform-aggregate`. Run
[`36378342000`](https://github.com/seifreed/r2morph/actions/runs/36378342000)
completed that aggregate with `5/5` platform reports and no failures. The
aggregate is a completeness gate for the declared preview cells; it does not
promote them to official parity. The current report contains six ARM32 cases,
seven AArch64 cases, seven x86 32-bit cases, twelve Windows PE cases, and
thirty-four macOS Mach-O/format cases. Every platform report has zero failures,
zero errors, and no missing required cases. ARM32 executes under QEMU and
AArch64 runs through the configured native/emulated runner path. This is
bounded execution evidence for the listed passes, not full-format parity.

The later complete run [43165336266](https://github.com/seifreed/r2morph/actions/runs/43165336266)
finished 85/85 jobs. Its core differential campaign covered 10 passes and
10,860 classified runs; the extended campaign covered 12 passes and 13,032
runs. Both recorded 100% semantic success with zero errors or failed seeds.
The public corpus aggregate covered 360 samples across four shards with no
differential or static-recovery failures. The preview platform aggregate
completed 5/5 slices and 73 JUnit cases; a separate VM semantic campaign passed
1,005/1,005 fixtures and QEMU pairs. The hash-bound summary and retained small
reports are in
[`protection-differential-run-2026-11-12-43165336266.json`](protection-differential-run-2026-11-12-43165336266.json).
These results strengthen bounded correctness evidence; they do not establish
full cross-platform parity or generalized resistance.
The current `main` run [`43340083394`](https://github.com/seifreed/r2morph/actions/runs/43340083394)
has independently validated all five declared preview platform jobs: 73 cases
across macOS ARM64, Windows PE, ELF ARM32, ELF AArch64, and ELF x86-32; every
job reports zero failures, errors, and skips. The hash-bound JUnit files and
per-job totals are retained in
[`protection-platform-preview-run-2026-11-13-c45eb58e.json`](protection-platform-preview-run-2026-11-13-c45eb58e.json).
This records only those five bounded preview jobs, not the workflow-wide
differential aggregate or full platform parity.

The successful workflow run [`43498875302`](https://github.com/seifreed/r2morph/actions/runs/43498875302)
on commit `b012cd0a` refreshed the full bounded campaign: the 10-pass core
recorded 10,860 classified runs and the 12-pass extended campaign recorded
13,032, both with 100% semantic success and zero failed seeds or errors. The
separate VM campaign passed 1,005/1,005 fixtures with 1,005 matching QEMU pairs.
The public corpus passed 360 samples over four shards and 2,160 static-recovery
measurements with no failures. Five preview platforms completed 73 cases with
no failures, errors, skips, or missing required cases. The hash-bound summary,
retained reports, and JUnit files are
[`protection-differential-run-2026-11-13-43498875302.json`](protection-differential-run-2026-11-13-43498875302.json).
The preview remains bounded and does not establish full platform parity. The
run still records 22 decompiler evidence blockers, and these correctness results
do not establish general resistance.

The Windows job now builds 32-bit PEs with MinGW and runs them under native
Windows or Wine. Local 2026-11-12 regressions passed for NOP insertion, the
four individual instruction, register, expansion, and constant-unfolding
passes, with original-versus-mutated output and repaired PE integrity checks.
These are preview cells only; the expanded Windows workflow must complete
before its artifacts are published.
The AArch64 campaign also includes a compiled C fixture with stack memory,
direct and indirect calls, a loop, and the same four-pass composition; the
compiled case is an additional evidence point, not a support promotion.
The Windows PE preview job also executes a real NOP-plus-register-substitution
composition and validates the repaired PE checksum; it remains preview evidence
and does not promote PE to the official support tier.
The current differential run [`43339101882`](https://github.com/seifreed/r2morph/actions/runs/43339101882)
has completed its Windows PE preview slice (17 tests) and ARM32 preview slice
(6 tests), with no failures, errors, or skips. The retained JUnit reports and
hash-bound summaries are the Windows PE report
[`protection-windows-pe-differential-preview-2026-11-13-92c6fef0.xml`](protection-windows-pe-differential-preview-2026-11-13-92c6fef0.xml)
and its summary
[`protection-windows-pe-differential-preview-2026-11-13-92c6fef0-summary.json`](protection-windows-pe-differential-preview-2026-11-13-92c6fef0-summary.json),
and the ARM32 report
[`protection-elf-arm32-differential-preview-2026-11-13-92c6fef0.xml`](protection-elf-arm32-differential-preview-2026-11-13-92c6fef0.xml)
with its summary
[`protection-elf-arm32-differential-preview-2026-11-13-92c6fef0-summary.json`](protection-elf-arm32-differential-preview-2026-11-13-92c6fef0-summary.json).
This is bounded preview evidence only; the full differential workflow and
cross-platform parity criterion remain open.
On 2026-11-10, the same PE test module ran locally on macOS 27.2 ARM64 with
MinGW-w64 GCC 16.2 and Wine 11.0: seven generated-binary mutation tests passed
and the Windows-only fixture test was skipped. This confirms an additional
Wine execution path; it is not native Windows evidence or a PE parity claim.
The PE block-reordering regression now builds a separate control-flow fixture,
executes the original and mutated images under native Windows or Wine for nine
inputs, and validates the repaired PE checksum and integrity. A passing local
run is preview evidence for this pass/target cell only; it does not promote
PE x86-64 to parity with Linux ELF x86-64.
On 2026-11-10, a connected licensed static-analysis service inspected the
original and CodeVirtualization-protected `elf_x86_64` fixture. The bounded
function and decompilation observations are in
[`protection-independent-analysis-2026-11-10.json`](protection-independent-analysis-2026-11-10.json).
The service did not expose its version; runtime equivalence was not measured.
This one-fixture result does not establish general resistance or replace the
three-analyzer release campaign.
On 2026-11-11, IDA Pro analyzed five original/protected ELF x86-64 fixture
pairs after one seeded CodeVirtualization pass each. It discovered and
decompiled the non-thunk `_start` function in all five protected outputs. The fixture hashes,
function counts, seeds, and exact limits are recorded in
[`protection-ida-targeted-2026-11-11-c70a113b.json`](protection-ida-targeted-2026-11-11-c70a113b.json).
The IDA Pro version was not exposed; this bounded run is analyzer coverage,
not a devirtualization-resistance result or a replacement for the full campaign.
The completed adversarial benchmark run
[`42987427831`](https://github.com/seifreed/r2morph/actions/runs/42987427831)
extends the run to 22 passes and 7,964 pass rows over repository fixtures plus
200 generated ELF x86-64 and C++ fixtures. All 22 passes have comparable
radare2, angr, and Ghidra evidence; the campaign recorded 2,341 applied passes,
zero pass errors, and no missing pass or analyzer rows. Triton completed all
7,964 analyzer runs; Unicorn completed 7,436 (93.37%). Of 71,676 expected
analyzer runs, 55,220 completed overall (77.04%), leaving 16,456 explicitly
unavailable runs and 17 evidence blockers: Binary Ninja's module and IDA Pro's
executable were unavailable, Unicorn could not execute 528 fixture runs, and
angr lacked three decompiler baselines. The pinned summary records the source report hash,
tool coverage, blockers, and VM smoke reports in
[`protection-adversarial-campaign-2026-11-11-4749bca3.json`](protection-adversarial-campaign-2026-11-11-4749bca3.json).
The accompanying 15-fixture, ten-seed VM campaign observed semantic parity,
distinct artifacts, opcode/handler/dispatcher diversity, tamper divergence,
and progressive growth on six fixtures. It is automated smoke evidence only:
the report retains pending independent adversarial validation and does not
establish general resistance.
The cross-format matrix additionally exercises `basic` and `complex` CFG
variants for those three ELF targets across the same four individual passes.
The workflow pins the collected matrix at 73 cases so loss of a preview corpus
variant or a Tier 1 composition case is treated as evidence drift rather than
silently reducing coverage. The added composition cases apply NOP insertion
before each other Tier 1 pass on ARM32, AArch64, and x86 32-bit fixtures.

The matrix covers GCC and Clang, `-O0`, `-O1`, `-O2`, `-O3`, and `-Os`, PIE and
non-PIE, symbol-preserving and stripped outputs, dynamic linking, and static
linking when the host toolchain provides it. C and C++ fixtures exercise switch
dispatch, loops, recursion, pointers, TLS, and C++ exceptions.

The repository-local generated differential campaign adds 200 deterministic
ELF x86-64 fixtures across those compiler profiles. The C subset includes a
dedicated SSE2 SIMD family so vector register and packed-integer paths remain
visible in the differential inventory, plus a pthread/atomic family that
exercises thread creation, joining, and shared-state ordering. The C++ subset includes a
separate exception/unwinding family compiled with native unwind metadata; this
keeps exception-bearing functions in the corpus while requiring the
virtualizer to preserve or reject them explicitly instead of treating a
partially transformed function as successful evidence. The VM semantic parity
campaign includes the generated compiler corpus and the repository fixtures;
the exception/unwinding family remains covered by the dedicated exception gate
and is excluded from the fully virtualized parity set. Stripped compiler
runtime helpers outside analyzed CFG blocks are ignored, while unsupported user
functions remain fail-closed and visible in the campaign report.
The seven real Linux x86-64 C++ exception-gate cases pass natively at commit
`d48d5341`; the bounded result is covered by the existing
[`test_code_virtualization_exception_gate_real.py`](../tests/integration/test_code_virtualization_exception_gate_real.py)
contract. The generated exception corpus adds sixteen GCC/Clang profiles with
one deterministic seed; all sixteen transform, preserve runtime and semantic
observables, and provide complete evidence in
[`protection-lsda-generated-cpp-2026-09-23-705bd5d0.json`](protection-lsda-generated-cpp-2026-09-23-705bd5d0.json).
This closes the declared LSDA/landing-pad gate for the generated Linux ELF
x86-64 C++ corpus, not the broader cross-platform parity gap or unsupported
language/ABI combinations.

The repository also runs an out-of-corpus native regression at
[`test_code_virtualization_generic_isa_real.py`](../tests/integration/test_code_virtualization_generic_isa_real.py).
It builds twenty-two temporary ELF x86-64 images: nine C images covering GCC
`-O0`, `-O1`, `-O2`, `-O3`, `-Os`, a frame-pointer-preserving GCC `-O2`, PIE,
stripped output, and Clang `-O2`; three scalar floating-point images covering
GCC `-O0`, GCC `-O2`, and Clang `-O2`; two packed SSE2 images covering GCC and
Clang `-O2`; three call-graph images covering GCC `-O0`, GCC `-O2`, and Clang
`-O2`; plus five C++ images covering GCC `-O0`, `-O2`, `-O3`, `-Os`, and
Clang++ `-O2`. The C image exercises `imul`, `neg`, `not`, `cmp`, `sete`,
`movzx`, shifts, carry, rotates, and memory loads/stores; the floating-point
images exercise scalar multiply, add, and compare; the SSE2 images exercise
packed integer add, xor, and unaligned stores; the C++ image exercises
compiler-generated loops and `switch` control flow; the call-graph images
exercise direct calls, function pointers, and recursion. Each transformed image must
preserve the native result and, for the C image, stdout and stderr.

Each build record includes the source digest, compiler command, toolchain
version, status, omission reason when applicable, compiler stdout/stderr
digests, elapsed time, and output size/hash. The public CI then transforms and
compares every built record independently for ten selected passes:
BlockReordering, CodeVirtualization, ConstantUnfolding, ControlFlowFlattening,
DeadCodeInjection, InstructionExpansion,
InstructionSubstitution, NopInsertion, PatternSubstitution, and
RegisterSubstitution. It retains one
bounded matrix record per sample/pass pair and an aggregate result for each
pass. The scheduled workflow fails when a selected pass does not apply to at
least one fixture, so an unchanged output cannot count as evidence for that
pass. Pass summaries retain bounded omission/error reasons for comparable
campaign triage. The public compatibility matrix remains the ten-pass corpus
selection. The adversarial benchmark's `--passes all` selection now expands
to all 22 declared corpus and extended maturity passes; the extended maturity
smoke still supplies the per-pass runtime, size, duration, and static metric
gate. Its application classifier uses the same bounded generic mutation-counter
contract as the maturity harness (`total_injections`, `total_patched`,
`imports_hashed`, `blocks_moved`, `functions_outlined`, and string counters),
so a pass cannot be reported as a no-op merely because it exposes a
pass-specific counter.
The adversarial benchmark also measures Binary Ninja through its installed API
when a licensed installation is available; otherwise its row is explicitly
reported as unavailable rather than omitted. Binary Ninja is on hold for the
current milestone, so the unavailable row remains visible evidence of scope,
not a completed analyzer result.
The repository-local single-fixture refresh at `736c7895` records this
availability slot in
[`protection-adversarial-benchmark.json`](protection-adversarial-benchmark.json)
(`SHA-256 d73a447dd8ee846d63641f2f0fbc5110346e50fbf137d55cdd0d644238e7553f`):
`angr`, Unicorn, radare2, objdump, and the custom analyzer completed, while
Binary Ninja, IDA, Ghidra, and Triton are explicit local availability gaps.
The focused local refresh at `59898697` repeats the
`elf_vm_fppackedidxnb_x86_64` CodeVirtualization fixture with `angr` installed:
`angr`, Unicorn, radare2, objdump, and the custom analyzer completed on both
original and protected binaries, and the protected image preserved exit code 6.
The bounded record is
[`protection-adversarial-angr-local-2026-09-18-59898697.json`](protection-adversarial-angr-local-2026-09-18-59898697.json)
(`SHA-256 14b0f716a5f8d32d23eb2bc3f7c8bd9f556b558138d77f962f24496b55d9a085`).
The full local refresh on 2026-09-20 measured all 162 repository fixtures for
`CodeVirtualization`. `angr` completed 162/162 runs with zero error rows;
radare2, objdump, and the custom analyzer also completed all runs. Unicorn
completed 155/162 runs and reported seven unavailable rows because its
installed x86 emulator could not execute an instruction in those fixtures.
Binary Ninja, IDA, Ghidra, and Triton remained unavailable in the local
environment. The bounded report is
[`protection-adversarial-angr-local-2026-09-20.json`](protection-adversarial-angr-local-2026-09-20.json)
(`SHA-256 793a2e48a19274d9efad6ab84aea4f00c740678fa7aa24c5ae5e68f48ea5f1ba`).
Corpus benchmark reports also aggregate completed, unavailable, error, changed,
bounded unavailable/error reasons, duration pair counts and totals, comparable
numeric metric pair counts, and numeric original-versus-protected metric deltas
per analyzer so campaigns remain comparable by tool. Their top-level summary
also records expected versus observed pass/tool counts and run counts for
campaign coverage, including the expected and observed analyzer names, coverage percentages, missing names, and
applied/omitted/error pass rates, counts, and reasons, per-pass/per-tool run
counts, plus completed/unavailable/error tool rates, counts, and reasons by
analyzer, completed-tool coverage over expected pass/tool slots, and
non-completed-tool gaps by analyzer. It also lists incomplete tool coverage
rows with completed, missing, unavailable, and error run counts for each analyzer
that lacks full comparable coverage.
The real VM diversification regression builds the same fixture with four
independent seeds, requiring identical emulated exit behavior and four distinct
output digests. This covers the combined opcode, handler, dispatcher, checksum,
and bytecode scheme rather than treating seed selection as an untested option.
It also requires each diversified build to report non-empty VM bytecode payloads
with zero unsupported or partial virtualizations.
Raw sample bytes and unbounded process output are not stored in reports. Each
transformation record includes the pass name, status (`applied`, `omitted`, or
`error`), a bounded reason, and severity when the selected pass cannot
transform the sample. Unsupported-virtualization diagnostics identify the
function address, instruction address, missing capability, reason, and severity.
Partial-virtualization diagnostics are rendered with the same bounded
capability, reason, and severity contract instead of falling back to a generic
omission.
Protection maturity runs retain bounded unsupported and partial-virtualization
capability/severity counts when the pass reports diagnostic records.
Adversarial CodeVirtualization rows and pass summaries also retain bounded
unsupported and partial virtualization capability/severity counts when
diagnostics are present. A partial-only virtualization result is classified as
an omitted pass with its diagnostic reason, not as a no-op.
CodeVirtualization pass stats also expose unsupported and partial diagnostic
capability and severity totals directly, so release gates can fail on closed
semantic gaps without expanding every diagnostic row.
Each unsupported-function diagnostic keeps the rejected instruction address,
mnemonic, type, size, and a bounded opcode preview alongside the capability and
reason.

The differential contract is original versus transformed execution across nine
seed-derived command-line inputs per sample: exit code, stdout, stderr, created
files, and declared observable effects must match. A failed comparison is a
release failure for the official Linux ELF x86-64 target.
The per-pass summary also aggregates runtime-observable coverage and pass/fail
counts, output-size coverage and deltas, transform/runtime duration coverage
and totals, static analyzer metric coverage and deltas, complete-evidence
coverage, coverage percentages, bounded runtime-observable failure reasons,
and bounded omission/error reasons and severities.
The by-pass report also includes a campaign summary with total applied,
omitted, and error runs, their rates, plus average coverage percentages across selected
passes, complete/missing metric-run totals grouped by metric, aggregate size/performance/static
metric deltas across selected passes, and aggregate semantic success/failure rates; it records expected,
covered, and missing corpus passes so subset campaigns cannot be mistaken for
full per-pass evidence, and lists passes with zero applied runs, omitted runs,
and error runs so
weak per-pass evidence is visible without expanding every row. It also groups
passes with incomplete runtime, size, duration, or static-metric coverage, plus
passes with semantic or runtime-observable failures, and records
runtime-observable failure reasons, omission/error reasons, and severities by
pass. Complete-evidence coverage requires the same run to have runtime, size,
transform-duration, runtime-duration, and static analyzer evidence.
The scheduled and main-push differential workflow validates this campaign summary before
uploading the artifact. It runs eight deterministic fixture shards across three
seeds in parallel, so the full 161-fixture repository corpus and all selected
passes remain covered without a monolithic job timing out. Each shard records
its `fixture_shard` index and count in `corpus_scope`; shard reports are not
merged into a false single-run success. Validation includes the Linux ELF
x86-64 platform scope,
`fixtures/dataset` corpus scope, generated corpus family coverage across branch,
extended, memory, implicit-string-memory, lookup-table, call, ABI, and stack-string fixtures compiled
with GCC `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, PIE, static, and stripped variants,
Clang `-O0`, `-O2`, `-O3`, and PIE variants, plus GCC and Clang++ C++ `-O0` and
`-O2` variants. The generated fixtures are reported under the distinct
`generated-elf-x86-64` and `generated-cpp-x86-64` corpus families, so C++
coverage cannot be mistaken for another C-only compiler variant. The campaign
also records generated argv input coverage,
the PE/Mach-O and ARM/AArch64/x86 platform gap scope, missing
corpus passes and incomplete coverage groups, plus a compact
`continuous_evidence_blockers` map and `continuous_evidence_blocker_totals`
counts, including `total_continuous_evidence_blockers`; the scheduled or main-push campaign
fails on unexpected official-target evidence blockers while retaining the
declared platform blockers as release gaps. The same
workflow also emits an
`extended-maturity-passes` smoke artifact for the non-default maturity passes:
AntiDisassembly, APIHashing, CodeMobility, DataFlowMutation,
FunctionOutlining, ImportObfuscation, OpaquePredicates, PolymorphicEngine,
SelfModifyingCode, ShortJumpPatching, StackStrings, and StringObfuscation.
That artifact is evidence triage only and records `missing_extended_passes`,
`passes_without_extended_applied_runs`, `extended_passes_with_error_runs`, and
`extended_maturity_evidence_blockers`, with
`total_extended_maturity_evidence_blockers` as the compact total; it fails on
extended pass errors, missing applications, behavioral false positives, or
missing runtime observations. It does not promote those passes until their
applied-run, behavioral-validation, and complete-evidence blockers are zero.
The same scheduled workflow now runs a native ARM64 macOS differential job on
`macos-latest` (currently the `macos-26-arm64` image); GitHub retired the
`macos-14` runner label on November 2, 2026 ([announcement](https://github.blog/changelog/2026-10-01-github-actions-macos-14-runner-image-retirement/)).
It executes the Mach-O ARM64 NOP and register substitutions, including a native
NOP-plus-instruction-substitution composition, PE integrity checks,
format-preserving rewriter checks, and fail-closed virtualization target
checks, then uploads
`cross-platform-differential-macos-arm64`. This is additional native
cross-platform evidence; it does not promote PE, Mach-O, ARM, or AArch64 to
the official Linux ELF x86-64 support tier. The platform evidence aggregator
also records that composition as a distinct macOS ARM64 pass-level row, so it
cannot disappear when the per-platform reports are merged.

The successful run [34790660315](https://github.com/seifreed/r2morph/actions/runs/34790660315)
at commit `4ffa6647` is the current continuous-evidence record. Its official
Linux ELF x86-64 corpus recorded zero runtime-observable failures, zero semantic
failures, and zero missing complete-evidence runs for all ten selected passes;
the report SHA-256 is
`8b0660a042bc1e33090f16ed25e9b33aefa52f9f07912508a1facd2a283ff207`. The same
run executed 21 cross-format cases with no failures and a six-order real-pass
composition matrix with no failures. Six cross-format cases remain skipped on
the Linux runner where native platform execution is unavailable, so this record
does not close the declared PE/Mach-O or ARM/AArch64/x86 parity gaps.

The newer campaign [36246458755](https://github.com/seifreed/r2morph/actions/runs/36246458755)
at commit `c7ef761a` has already completed its native platform and VM semantic
artifacts without failures. The platform aggregate records six complete pass
rows for each of ELF ARM32, ELF x86-32, macOS ARM64, and Windows PE, plus six
for ELF ARM64; the merged VM semantic artifact is `passed` for 1,005 cases
across three seeds. These are partial campaign artifacts while the public
compatibility matrix is still running; they do not close the broader
cross-platform, per-pass analyzer, or 15-fixture-by-10-seed release gaps.

The adversarial campaign summary records distinct completed, unavailable, and
errored analyzer tools, so completed `angr` or Triton runs are not hidden behind
environment-specific IDA, Ghidra, or Binary Ninja availability gaps. It also
records completed-run coverage by analyzer tool so campaigns remain comparable
when a licensed or local analyzer is missing. A compact
`adversarial_evidence_blockers` map records missing pass rows, passes without
applications, pass errors, incomplete tool coverage, unavailable analyzer
runs with reasons, and non-completed analyzer runs. Companion
`adversarial_evidence_blocker_totals` counts, including
`total_adversarial_evidence_blockers`, keep the remaining signoff blockers
visible without expanding every row; both must be zero before the adversarial
benchmark can support release signoff.
Single-fixture benchmark artifacts also expose `release_signoff_blockers` and
`release_signoff_blocker_totals`, including `total_release_signoff_blockers`,
so unavailable analyzer slots cannot be mistaken for completed adversarial
coverage.
The scheduled adversarial workflow validates the campaign summary before upload
so missing pass/tool rows and missing applications for the ten contractual
corpus passes fail the run. It also starts automatically after a successful
`Differential Corpus By Pass` run and checks out that run's exact `head_sha`,
so analyzer evidence is refreshed for the same source revision rather than
drifting behind the differential campaign. It includes the same 200 generated ELF
x86-64 variants used by the differential campaign, records the distinct
`generated-elf-x86-64` and `generated-cpp-x86-64` families in the merged report,
and partitions generated fixtures together with repository fixtures. Extended-
pass application gaps remain published as explicit evidence blockers.
Decompiler effectiveness is counted twice: the full sample pair remains
visible, while the release gate also requires complete `radare2`, `angr`, and
`ghidra` pairs for every fixture where the pass actually applied. No-op
fixtures cannot inflate per-pass decompiler evidence.
The campaign now runs as eight deterministic fixture shards. Each shard retains
all analyzer slots, while the aggregate job merges the eight reports, rejects
overlapping samples, and applies the application and row-completeness gates to
the full corpus. This keeps the evidence continuous without treating a
per-shard omission as a corpus-wide pass. The aggregate gate also requires
both generated corpus families after merging all shards.
The archived four-shard 22-pass aggregate
[`35021131440`](https://github.com/seifreed/r2morph/actions/runs/35021131440)
completed 11,682 pass rows (5,310 core and 6,372 extended) with zero missing or
error rows across the repository and generated ELF x86-64 fixtures. All
output-size, duration, static-metric, runtime-observable, and semantic fields
were complete. The public compatibility-corpus job is now a required input to
the differential aggregator, which validates its six-pass matrix and
static-recovery artifact before publishing merged evidence. The merged maturity
evidence retains ten independent false-positive gaps, eight composition gaps,
22 decompiler gaps, and one pass without an applied instruction catalogue;
these are archived totals, not current release blockers. The authoritative
adversarial run `36381653200` records all 22 passes as comparable, with
`7,964/7,964` expected pass rows and complete `radare2`, `angr`, and `ghidra`
evidence for every pass. The current 46-case composition smoke adds applied
evidence for seven of those eight historical composition gaps.

The companion adversarial aggregate
[`34999775170`](https://github.com/seifreed/r2morph/actions/runs/34999775170)
completed all four shards and aggregate validation without transformation or
analyzer errors. Binary Ninja, IDA Pro, and Ghidra remained unavailable, while
132 Unicorn rows reported explicit ISA-capability gaps. The unavailable and
partial-ISA rows remain release blockers.

The scheduled differential workflow uses the same eight-shard model across
three seeds. Generated ELF fixtures are partitioned with repository fixtures,
and the aggregate artifact rechecks that all 200 generated variants and all
pass/fixture/seed rows are present before publishing the campaign evidence.
The secondary JUnit evidence therefore contains 24 reports (eight shards across
three seeds). In-process analyzer adapters run in isolated workers with a
bounded 90-second pair budget; a timeout is retained as an analyzer error row,
never silently converted into an unavailable or missing row.
Each VM semantic fixture runs in an isolated worker with a bounded
transformation timeout; a stuck or killed worker is recorded as failed
evidence and cannot leave the scheduled job running indefinitely.

The latest repository-fixture campaign against `8b6cfb40` covered 159 fixtures
and the six selected passes available at that commit. Its per-pass summary is committed in
[`protection-maturity-by-pass-2026-09-04-8b6cfb40.json`](protection-maturity-by-pass-2026-09-04-8b6cfb40.json),
from workflow `33907747531` (artifact SHA-256
`606d4be7f8f91a89bd37ef77cce149ee8c2e3e332f21eec296d38314443713a6`). All six
passes recorded 159 semantic passes with no failures. The corrected
`elf_vm_fppackedidxnb_x86_64` baseline and transformed binary both return 6 in
native and Unicorn execution.
The ConstantUnfolding, ControlFlowFlattening, DeadCodeInjection, NopInsertion,
and PatternSubstitution selections are guarded by `elf_constant_unfold_x86_64`,
`elf_cff_flagdead_x86_64`, and `elf_nop_x86_64`. They are measured from this
revision onward; a full ten-pass campaign is required before this document
claims a complete Linux CI record.
The preceding local CodeVirtualization rerun at `bb3eb3bf` covered 159 fixtures
and all 159 transformations, with 171 functions virtualized, zero unsupported
functions, and zero transformation errors. Its raw report is
[`protection-adversarial-corpus-2026-09-05-bb3eb3bf.json`](protection-adversarial-corpus-2026-09-05-bb3eb3bf.json)
(`SHA-256 6a6c4b447d0a1abf6fb56b2f24c4be724288bc86d28144793ef8a645a188b94f`),
with the compact summary in
[`protection-adversarial-corpus-2026-09-05-bb3eb3bf-summary.json`](protection-adversarial-corpus-2026-09-05-bb3eb3bf-summary.json).
The current rerun at `7c3d4f32` repeats the complete CodeVirtualization corpus
after the terminal-syscall and floating-point tail fixes: 159/159 samples
applied, 171 functions virtualized, zero unsupported functions, and zero
transformation errors. It recorded 939 completed analyzer runs, 15 Unicorn
errors, and 318 explicit IDA/Ghidra-unavailable rows. The raw report is
[`protection-adversarial-corpus-2026-09-05-7c3d4f32.json`](protection-adversarial-corpus-2026-09-05-7c3d4f32.json)
(`SHA-256 38143a56c34683d95fed3cbd0fbea0553d710228dac80b6ab857638466908180`).
The reproducible local rerun at `66ba4745` repeats the same 159/159
CodeVirtualization campaign with 171 functions virtualized, zero unsupported
functions, and zero transformation errors. It completed 939 tool runs; the
15 recorded tool errors are `UcError` results from the Unicorn emulator on
AVX/VEX fixtures, while the corresponding native regression tests remain the
authoritative execution check. IDA and Ghidra are explicitly unavailable in
this local environment (318 rows), not silently treated as passes. The raw
report is
[`protection-adversarial-corpus-2026-09-05-66ba4745.json`](protection-adversarial-corpus-2026-09-05-66ba4745.json).
The licensed IDA MCP and local Ghidra campaigns are recorded separately below.
The latest local Ghidra headless campaign for the 159-fixture corpus at
`88258a05` completed 318 analyses with zero errors or timeouts. Its raw report is
[`protection-ghidra-corpus-2026-09-04-88258a05.json`](protection-ghidra-corpus-2026-09-04-88258a05.json),
with the per-run contract in
[`protection-ghidra-corpus-2026-09-04-88258a05-summary.json`](protection-ghidra-corpus-2026-09-04-88258a05-summary.json)
and SHA-256
`cd86ada75b515f84676bb110807cf8d964276cb5bda54831750aec70d28c5f25`.
The corresponding public workflow `33259983358` was cancelled before its
Ghidra benchmark completed; the local raw report above is therefore the
authoritative Ghidra evidence.

The preceding IDA MCP rerun at `bb3eb3bf` completed all 159 original and all
159 CodeVirtualization-protected fixtures, for 318 analyses with zero errors.
The current rerun at `7c3d4f32` repeats those 318 analyses with zero errors and
recovers 210 functions across originals and 380 across protected outputs. The
aggregate evidence is in
[`protection-ida-mcp-corpus-2026-09-05-7c3d4f32.json`](protection-ida-mcp-corpus-2026-09-05-7c3d4f32.json)
(`SHA-256 b2dd4fc1328569708f49d32a58982f90e623b1c2c63111c5006cf4e84b29448d`).

The current-state detailed rerun at `0a1a4bfd` repeats all 159 original and
CodeVirtualization-protected fixtures, for 318 IDA MCP analyses with zero
errors. It recovers 210 functions across originals and 378 across protected
outputs. The raw record is
[`protection-ida-mcp-corpus-2026-09-06-0a1a4bfd.json`](protection-ida-mcp-corpus-2026-09-06-0a1a4bfd.json)
(`SHA-256 20db206e0c02165c0ffa9ef100098118cbdedcacad665fb6143d7dc88d3b721d`).

The latest detailed rerun at `a7512ec5` repeats the same 318 IDA MCP analyses
with zero errors. It recovers 210 functions across originals and 378 across
protected outputs, including 1 original and 9 protected functions for
`elf_vm_fppackedidxnb_x86_64`. The raw record is
[`protection-ida-mcp-corpus-2026-09-06-a7512ec5.json`](protection-ida-mcp-corpus-2026-09-06-a7512ec5.json)
(`SHA-256 b2f636980800ca6c15c675e72ef4eb364708a28cb19611e52dae61156da91ace`),
with the bounded summary in
[`protection-ida-mcp-corpus-2026-09-06-a7512ec5-summary.json`](protection-ida-mcp-corpus-2026-09-06-a7512ec5-summary.json).

The post-unwind-metadata rerun at `6de7999e` repeats all 318 IDA MCP analyses
with zero errors and recovers 210 functions across originals and 378 across
protected outputs. The raw record is
[`protection-ida-mcp-corpus-2026-09-06-6de7999e.json`](protection-ida-mcp-corpus-2026-09-06-6de7999e.json)
(`SHA-256 bc7ad24ee4f65cd06ded5eb8416a3535198579218ea4423794a15b77df3f5c4b`),
with the bounded summary in
[`protection-ida-mcp-corpus-2026-09-06-6de7999e-summary.json`](protection-ida-mcp-corpus-2026-09-06-6de7999e-summary.json).

The current IDA MCP rerun at `646e0942` repeats all 159 original and
CodeVirtualization-protected fixtures with `318/318` completed analyses and
zero errors. It recovers 210 functions across originals and 378 across
protected outputs, including 1 original and 9 protected functions for
`elf_vm_fppackedidxnb_x86_64`. Binary Ninja was not measured in this historical IDA-only artifact. The raw
record is
[`protection-ida-mcp-corpus-2026-09-06-646e0942.json`](protection-ida-mcp-corpus-2026-09-06-646e0942.json)
(`SHA-256 62614c89fb6e4db2719a360d2242335defac27d514a6daa7fde5f1ac0974e8e1`),
with the bounded summary in
[`protection-ida-mcp-corpus-2026-09-06-646e0942-summary.json`](protection-ida-mcp-corpus-2026-09-06-646e0942-summary.json)
(`SHA-256 0d8b61a6714bda997d369d2b098a10345f9149463b99814c06f13c9db1202eba`).

The latest Linux rerun at `83e6eee6` used `triton-library 1.0.0rc4` in the
reproducible Python 3.13 virtualenv and completed 954 original/protected pair
records for Triton and 954 for angr across all 159 fixtures and six passes.
Both tools reported zero error or unavailable records. The raw report is
[`protection-adversarial-corpus-2026-09-05-83e6eee6-triton.json`](protection-adversarial-corpus-2026-09-05-83e6eee6-triton.json)
(`SHA-256 d8979e3285959f7b3683a6be03b8358a6aaeb45e3b7e2ddbb2fd1c3d0685a2a0`).
The full report still records 5,679 completed tool runs, 45 Unicorn errors,
and 1,908 unavailable-tool rows; the latter are explicit environment/tool
availability results, not Triton or angr failures.

The current rerun at `44bca563` repeats all 159 fixtures and six passes with
the Python 3.13 virtualenv containing `triton-library 1.0.0rc4`. It records
159/159 CodeVirtualization applications, 171 virtualized functions, and zero
unsupported functions. Triton and angr complete every configured pair; the
47 errors are isolated to Unicorn (`UcError`), and the 1,908 unavailable rows
are the local IDA/Ghidra executables. Binary Ninja was not measured in this historical run.
The raw report is
[`protection-adversarial-corpus-2026-09-05-44bca563-triton.json`](protection-adversarial-corpus-2026-09-05-44bca563-triton.json).

The latest rerun at `a92e8b9` repeats all 159 fixtures and six passes after the
carry-control flag semantics update. It records 159/159 CodeVirtualization
applications, 171 virtualized functions, and zero unsupported functions.
Triton and angr complete every configured pair; the 47 errors remain isolated
to Unicorn, and the 1,908 unavailable rows remain the local IDA/Ghidra
executables. Binary Ninja was not measured in this historical run. The raw report is
[`protection-adversarial-corpus-2026-09-05-a92e8b9-triton.json`](protection-adversarial-corpus-2026-09-05-a92e8b9-triton.json).

This `fa85d18` rerun repeats the same corpus after adding native `neg` flag
semantics. It records 159/159 CodeVirtualization applications, 171 virtualized
functions, and zero unsupported functions. Triton and angr complete every
configured pair; the 47 errors remain isolated to Unicorn, and the 1,908
unavailable rows remain the local IDA/Ghidra executables. Binary Ninja was not
measured in this historical run. The raw report is
[`protection-adversarial-corpus-2026-09-05-fa85d18-triton.json`](protection-adversarial-corpus-2026-09-05-fa85d18-triton.json).

The current `c820685f` rerun repeats the CodeVirtualization corpus after the
memory-destination carry semantics update. It records 159/159 applications,
171 virtualized functions, and zero unsupported functions. Triton and angr
complete all 159 original/protected pairs; 15 `UcError` rows are isolated to
Unicorn AVX/VEX emulation. IDA and Ghidra are explicitly unavailable in this
macOS run (318 rows), and Binary Ninja was not measured in this historical run.
The raw report is
[`protection-adversarial-corpus-2026-09-05-c820685f-triton.json`](protection-adversarial-corpus-2026-09-05-c820685f-triton.json)
(`SHA-256 f6244bf6aecfe115104857b53930b3478ec758ad3c65b65bfe43ba93fc77aaa4`).

The current deterministic parser/dispatcher/relocation/rewriter fuzz campaign
at `2e4ad8e` ran 20,000 cases per target, 80,000 target runs in total, with
zero failures. Its bounded report is
[`protection-fuzz-2026-09-05-2e4ad8e.json`](protection-fuzz-2026-09-05-2e4ad8e.json).

The current fuzz rerun at `cf44477` repeats 20,000 cases per target with seed
`20260906`, for 80,000 bounded executions and zero failures. It covers binary
parsers, the VM dispatcher, relocations, and binary rewriting. Its bounded
report is [`protection-fuzz-2026-09-06-cf44477.json`](protection-fuzz-2026-09-06-cf44477.json).

The current wheel-backed campaign passed at commit `95cff0fb` with seed
`20261111`: 20,000 cases per target across assembly, malformed binary inputs,
mutated ELF headers, PE optional headers, Mach-O load commands, VM dispatch and
bytecode generation, relocations, and rewriting, for 180,000 target runs with
zero failures. It records 413 expected parser warnings as counts and preserves
the logger state. The report and workflow run are
[`protection-fuzz-format-aware-2026-11-11-95cff0fb.json`](protection-fuzz-format-aware-2026-11-11-95cff0fb.json)
and [run 43067351979](https://github.com/seifreed/r2morph/actions/runs/43067351979).
This adds per-format parser depth; it does not establish semantic equivalence,
analyzer resistance, or platform parity. Earlier campaigns remain historical
evidence.

A source-tree rerun at commit `04e2f5b4` used seed `20261112` and completed
20,000 cases for each of the same nine targets (180,000 target runs, zero
failures). It recorded 428 recoverable Mach-O parser warnings as bounded
counts. The exact raw campaign output is
[`protection-fuzz-2026-11-12-04e2f5b4-output.json`](protection-fuzz-2026-11-12-04e2f5b4-output.json);
the metadata summary binds its SHA-256 and identifies this as a local source-tree
run, not a wheel-backed workflow. Reproduce it with
`python scripts/continuous_fuzz.py --cases 20000 --seed 20261112 --output fuzz-campaign.json`.
This adds current fuzz evidence but does not establish semantic equivalence,
complete cross-platform fuzz coverage, analyzer resistance, or platform parity.

The wheel-backed workflow reran the same 180,000-target campaign on commit
`8d6ceb6a` with seed `20261112`. The built wheel was installed in a clean
directory, all nine targets completed 20,000 cases each with zero failures,
and 428 recoverable Mach-O warnings were retained as counts. The verified run
is [43132685797](https://github.com/seifreed/r2morph/actions/runs/43132685797);
its downloaded raw output and hash-bound summary are
[`protection-fuzz-wheel-2026-11-12-8d6ceb6a-output.json`](protection-fuzz-wheel-2026-11-12-8d6ceb6a-output.json)
and
[`protection-fuzz-wheel-2026-11-12-8d6ceb6a.json`](protection-fuzz-wheel-2026-11-12-8d6ceb6a.json).
This confirms installed-wheel fuzz coverage, not cross-platform semantic
equivalence or general resistance.

The follow-up run [43160969902](https://github.com/seifreed/r2morph/actions/runs/43160969902)
ran that same wheel-backed campaign on Ubuntu, macOS ARM64, and Windows. Each
runner completed all nine targets at 20,000 cases per target: 540,000 target
runs overall, zero failures, and 428 counted recoverable Mach-O warnings per
runner. The raw campaign reports and hash-bound platform summary are
[`protection-fuzz-wheel-platform-2026-11-12-df55c7a6.json`](protection-fuzz-wheel-platform-2026-11-12-df55c7a6.json),
[`ubuntu`](protection-fuzz-wheel-platform-2026-11-12-df55c7a6-ubuntu.json),
[`macOS`](protection-fuzz-wheel-platform-2026-11-12-df55c7a6-macos.json), and
[`Windows`](protection-fuzz-wheel-platform-2026-11-12-df55c7a6-windows.json).
This closes the declared wheel-fuzz execution matrix for these three runners;
it does not establish cross-platform semantic parity or general resistance.

Run [43331412474](https://github.com/seifreed/r2morph/actions/runs/43331412474)
repeated the nine-target, 20,000-case installed-wheel campaign on current `main`
commit `134af4ff`: 540,000 total target runs and zero failures across Ubuntu,
macOS ARM64, and Windows. The reports and their hashes are retained in
[`protection-fuzz-wheel-platform-2026-11-13-134af4ff.json`](protection-fuzz-wheel-platform-2026-11-13-134af4ff.json)
and its three runner reports. This binds the existing fuzz scope to current
`main`; it does not broaden that scope or establish semantic parity or
resistance.

Commit `03984513` adds a separate `vm_instruction_decoder` target. The local
Python 3.13.11 source-tree run completed 5,000 cases on each of ten fuzz targets
(50,000 target runs, zero failures); the raw report and hash-bound summary are
[`protection-fuzz-vm-decoder-2026-11-14-03984513-output.json`](protection-fuzz-vm-decoder-2026-11-14-03984513-output.json)
and
[`protection-fuzz-vm-decoder-2026-11-14-03984513.json`](protection-fuzz-vm-decoder-2026-11-14-03984513.json).
The installed-wheel workflow for this commit completed successfully on Ubuntu,
macOS ARM64, and Windows in
[run 43527087277](https://github.com/seifreed/r2morph/actions/runs/43527087277).
It covered ten targets with 5,000 cases each per runner (150,000 target runs
total), with zero failures and 103 counted recoverable Mach-O parser warnings
per runner. The three raw reports and their hash-bound aggregate are recorded
in
[`protection-fuzz-vm-decoder-platform-2026-11-14-03984513.json`](protection-fuzz-vm-decoder-platform-2026-11-14-03984513.json).
This adds wheel-backed decoder fuzz evidence on all three runners; it does not
establish semantic equivalence, platform parity, or general resistance.

A second host analyzer shard ran CodeVirtualization on 11 additional ELF x86-64
fixtures. All 11 transformations applied without unsupported functions or pass
errors. IDA Pro 9.5, Ghidra 12.2, angr, Unicorn, radare2, objdump, and the custom
analyzer completed 77/77 available runs with zero tool errors; Binary Ninja and
Triton were unavailable, leaving 22/99 expected slots unavailable. The pinned
report is
[`protection-host-adversarial-shard-2026-11-11-b8d112a7-shard-01.json`](protection-host-adversarial-shard-2026-11-11-b8d112a7-shard-01.json).
This adds one bounded fixture shard and does not establish all-pass analyzer
coverage or cross-platform parity.

A third deterministic host shard applied CodeVirtualization to ten more ELF
x86-64 fixtures, with no unsupported functions or pass errors. IDA Pro 9.5,
Ghidra 12.2, angr, radare2, objdump, and the custom analyzer completed all ten
original/protected pairs; Unicorn completed nine and reported one unsupported
instruction. The shard therefore completed 69/90 analyzer runs with zero tool
errors. Binary Ninja remained unavailable because the host license was
unavailable, and Triton was not installed. Its pinned report and regression
checks are
[`protection-host-adversarial-shard-2026-11-11-c5b590cc-shard-02.json`](protection-host-adversarial-shard-2026-11-11-c5b590cc-shard-02.json)
and [`test_published_host_adversarial_shard.py`](../tests/unit/test_published_host_adversarial_shard.py).
This adds fixture-level evidence only; it does not close all-analyzer coverage,
the independent resistance review, or platform parity.

A fourth deterministic host shard at `134af4ff` applied CodeVirtualization to
nine more repository fixtures with zero unsupported functions, partial
virtualizations, or pass errors. IDA Pro 9.5, Ghidra 12.2, angr, Unicorn,
radare2, objdump, and the custom analyzer completed 63/63 available runs with
zero report error rows. angr emitted unsupported `amd64g_dirtyhelper_IN` and
`amd64g_dirtyhelper_OUT` diagnostics, so its completed decompiler measurements
are bounded and are not semantic-equivalence evidence. Binary Ninja was
unavailable because its license was invalid, and Triton was unavailable
because the module was not installed, leaving 18/81 expected analyzer runs
unavailable. The raw output and
hash-bound summary are
[`protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13.json`](protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13.json)
and
[`protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13-summary.json`](protection-host-adversarial-shard-2026-11-13-134af4ff-shard-13-summary.json).
This adds nine fixture-level pairs; it does not complete the all-pass analyzer
matrix or establish generalized resistance.

The follow-up at current `main` commit `24b306ee` ran all 22 declared passes
over the same nine-fixture shard. It recorded 198 pass rows: 17 applied, 181
no-op, zero omissions, and zero pass errors. The seven available analyzers each
completed all 198 rows (1,386/1,782 runs); Binary Ninja and Triton were
unavailable for 198 rows each. angr emitted unsupported `amd64g_dirtyhelper_IN`
and `amd64g_dirtyhelper_OUT` diagnostics and could not infer some calling
conventions, limiting its decompiler measurements. The report and hash-bound
summary are
[`protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13.json`](protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13.json)
and
[`protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13-summary.json`](protection-host-adversarial-allpasses-2026-11-13-24b306ee-shard-13-summary.json).
This is one 9-fixture shard, not the full 362-sample matrix or generalized
resistance evidence.

The differential workflow at `019a0551` also completed its full 85-job
aggregate. Across the declared Linux ELF x86-64 corpus, it recorded 10/10 core
passes over 10,860 seeded runs, 3,565 applied transformations, zero errors,
zero semantic failures, and complete runtime-observable and evidence fields.
The same workflow also completed the 12 extended passes over 13,032 seeded
runs: 3,374 applications, 9,658 expected omissions, zero errors, zero semantic
or runtime-observable failures, and complete evidence for every run. All 12
passes applied at least once. Across applied runs, output size was unchanged;
the campaign recorded 3,573.11 seconds of aggregate transformation time. These
are observed costs on this Linux ELF x86-64 corpus, not controlled performance
benchmarks. The compact per-pass results and raw artifact digest are published
in [`protection-extended-differential-2026-11-11-019a0551.json`](protection-extended-differential-2026-11-11-019a0551.json).
Together, the core and extended reports cover all 22 declared passes for
published correctness and observed-cost evidence on this target. They do not
establish preview-platform parity or resistance to named analysts. The separate
public corpus matrix completed 360 samples across six selected passes and
2,160 radare2 static-recovery measurements with no differential or analyzer
failures; an omitted pass application is not counted as a transformation
success. The
compact result, source artifact digests, and workflow link are retained in
[`protection-differential-2026-11-11-019a0551.json`](protection-differential-2026-11-11-019a0551.json)
and [run 42980449435](https://github.com/seifreed/r2morph/actions/runs/42980449435).
The rerun from source commit `52dfc2eac82584149dcb6e4c83dd08fd03c040a6`
completed all four public-corpus shards and the aggregate validation job in
[run 43064188826](https://github.com/seifreed/r2morph/actions/runs/43064188826).
It reproduced the same 360 selected samples, six-pass outcomes, 2,160
differential checks, and 2,160 radare2 measurements with zero failures. This
confirms a repeatable run; it is not an additional 360-sample corpus expansion.
Per-shard manifest, matrix, and analyzer artifact hashes are pinned in
[`protection-public-corpus-2026-11-11-43064188826.json`](protection-public-corpus-2026-11-11-43064188826.json).
Its aggregate output-size growth is 64,374,555 bytes over 10,860 runs and the
campaign records 4,635.57 seconds of transformation time; these are raw
aggregate costs, not normalized per-binary or controlled performance claims.
The core report alone does not establish preview-platform parity or resistance
to named analysts.

The authoritative current CodeVirtualization rerun at `dbf77c59` repeats all
159 repository fixtures with the dedicated Python 3.13 virtualenv containing
`triton-library 1.0.0rc4`. It records 159/159 applications, 171 virtualized
functions, zero unsupported functions, and zero transformation errors. Triton
and angr complete every original/protected pair. The 15 tool errors are
isolated to Unicorn AVX/VEX emulation, and the 318 unavailable rows are the
local IDA/Ghidra executables. Binary Ninja was not measured in this historical run. The raw
report is
[`protection-adversarial-corpus-2026-09-06-dbf77c59-triton.json`](protection-adversarial-corpus-2026-09-06-dbf77c59-triton.json)
(`SHA-256 22410aa82448504a28964b9fa9e436a6014c8d2545f9adf9653f9c9a39ceecea`).

The current rerun at `76e144bb` repeats the same 159-fixture
CodeVirtualization campaign with the dedicated Python 3.13 virtualenv. It
records 159/159 applications, 171 virtualized functions, zero unsupported
functions, and zero partial virtualizations. Angr and Triton complete every
original/protected pair; the 15 tool errors are isolated to Unicorn, and the
318 unavailable rows are the local IDA/Ghidra executables. Binary Ninja was not
measured in this historical run. The named `elf_vm_fppackedidxnb_x86_64` regression
virtualizes one function and preserves exit code 6 in native and Unicorn
execution. The raw report is
[`protection-adversarial-corpus-2026-09-06-76e144bb-triton.json`](protection-adversarial-corpus-2026-09-06-76e144bb-triton.json)
(`SHA-256 5263384de9ba18f437b6e70a51cdbea9bc5f06ceaf8a4d4599627dcb808a3d1d`).

The current rerun at `51b949a` repeats the same 159-fixture CodeVirtualization
campaign after the precise unwind diagnostic update. It records 159/159
applications, 171 virtualized functions, zero unsupported functions, zero
partial virtualizations, and zero transformation errors. Angr and Triton
complete every configured original/protected pair; the 15 tool errors remain
isolated to Unicorn, and the 318 unavailable rows are the local IDA/Ghidra
executables. Binary Ninja was not measured in this historical run. The raw report is
[`protection-adversarial-corpus-2026-09-06-51b949a-triton.json`](protection-adversarial-corpus-2026-09-06-51b949a-triton.json)
(`SHA-256 f2cab32b9608a5490233b8b1f83c85f6f23f6ff45d66f907150a8ab8d6d29f11`).

The current rerun at `d82cc2b9` repeats the same 159-fixture CodeVirtualization
campaign with `triton-library 1.0.0rc4` in the Python 3.13 virtualenv. It
records 159/159 applications, 171 virtualized functions, zero unsupported
functions, zero partial virtualizations, and zero transformation errors. Angr
and Triton complete every original/protected pair; the 15 tool errors remain
isolated to Unicorn, while the 318 unavailable rows are the local IDA/Ghidra
executables. Binary Ninja was not measured in this historical run. The named
`elf_vm_fppackedidxnb_x86_64` regression virtualizes one function and preserves
exit code 6. The raw report is
[`protection-adversarial-corpus-2026-09-06-d82cc2b9-triton.json`](protection-adversarial-corpus-2026-09-06-d82cc2b9-triton.json)
(`SHA-256 f004d1c2c33e7484b93c52cee3357927bf27215ea221419819bfc43785f5f920`).

The focused IDA validation at `702450d7` covers the corrected
`elf_vm_fppackedidxnb_x86_64` regression. Original and protected execution
both return 6; IDA completes with 1 and 2 recovered functions respectively,
with zero errors. Angr and Triton also complete both binaries. The bounded
record is [`protection-fppackedidxnb-ida-2026-09-06-702450d7.json`](protection-fppackedidxnb-ida-2026-09-06-702450d7.json).
Binary Ninja was not measured in this historical run.

The full IDA MCP corpus rerun from the same code commit covers all 159 original
and CodeVirtualization-protected fixtures with zero analysis errors. IDA
recovers 288 functions across originals and 466 across protected outputs. This
is a bounded function-count benchmark; it does not claim decompiler or CFG
equivalence. Its aggregate record is
[`protection-ida-mcp-corpus-2026-09-06-702450d7.json`](protection-ida-mcp-corpus-2026-09-06-702450d7.json).

The benchmark contract was extended at `38bee7f` to report partial
virtualization explicitly. The rerun remains 159/159 applied with 171
virtualized functions, zero unsupported functions, and zero partial
virtualizations. Angr and Triton complete every configured pair; the 15
Unicorn errors remain isolated to AVX/VEX emulation and the 318 unavailable
rows are explicit local IDA/Ghidra availability records. The raw report is
[`protection-adversarial-corpus-2026-09-06-38bee7f.json`](protection-adversarial-corpus-2026-09-06-38bee7f.json)
(`SHA-256 d3fa995b1b58a9bee10d6acab4ac610e25d7bf8af083564866aa019d37585249`),
with the bounded summary in
[`protection-adversarial-corpus-2026-09-06-38bee7f-summary.json`](protection-adversarial-corpus-2026-09-06-38bee7f-summary.json).

The preceding Linux Triton rerun at `d0e63026` used the same package and
completed the same 954 Triton pair records; its raw report remains
[`protection-adversarial-corpus-2026-09-04-triton.json`](protection-adversarial-corpus-2026-09-04-triton.json)
(`SHA-256 cbfd6a78857622a5704d25938c16c32ac50d7adc269d0d3f02b3ff60e20107c4`).

The corpus workflow also runs a bounded static-recovery benchmark with
`radare2` over every passed original/transformed pair and pass, recording
function, basic-block, edge, instruction, and duration deltas without retaining
analyzer output. The latest successful public corpus run for the pinned corpus
is tracked in
[`33045740069`](https://github.com/seifreed/r2morph-corpus/actions/runs/33045740069).
The later replacement runs `33259963329` (corpus) and `33259983358` (Ghidra)
were cancelled before their validation steps completed. The local Ghidra
artifact and the current IDA MCP artifact above are the repository-fixture
evidence; angr and Triton have complete local repository-fixture runs.
Licensed local measurements remain separate from public-runner evidence.

The `bc2bff2` rerun repeats the CodeVirtualization corpus after changing the
default policy to reject unproven partial virtualization. It records 159/159
applications, 171 virtualized functions, zero unsupported functions, and zero
partial virtualizations. Angr and Triton complete every configured pair; the
15 errors remain isolated to Unicorn AVX/VEX emulation and the 318 unavailable
rows are explicit local IDA/Ghidra availability records. Binary Ninja was not
measured in this historical run. The raw report is
[`protection-adversarial-corpus-2026-09-06-bc2bff2.json`](protection-adversarial-corpus-2026-09-06-bc2bff2.json)
(`SHA-256 7c673f5cf52d7b6ee564b6a3d6aab59d7436af0e6f4590b27705db439ad031fc`),
with the bounded summary in
[`protection-adversarial-corpus-2026-09-06-bc2bff2-summary.json`](protection-adversarial-corpus-2026-09-06-bc2bff2-summary.json).

The current rerun at `43ba227c` repeats the same 159-fixture
CodeVirtualization corpus after scoping the unwind gate to the candidate VM
region. It records 159/159 applications, 171 virtualized functions, zero
unsupported functions, zero partial virtualizations, 939 completed analyzer
runs, 15 isolated Unicorn errors, and 318 explicit local IDA/Ghidra
availability rows. Angr and Triton complete every configured pair; Binary Ninja
was not measured in this historical run. The raw report is
[`protection-adversarial-corpus-2026-09-06-43ba227c.json`](protection-adversarial-corpus-2026-09-06-43ba227c.json)
(`SHA-256 83b90d71cc4db022ef81634e87d327279da71513984108a42dae3beb3b319d5c`),
with the bounded summary in
[`protection-adversarial-corpus-2026-09-06-43ba227c-summary.json`](protection-adversarial-corpus-2026-09-06-43ba227c-summary.json).

The post-unwind-metadata rerun at `6de7999e` repeats the same 159-fixture
CodeVirtualization corpus with 159/159 applications, 171 virtualized
functions, zero unsupported functions, and zero partial virtualizations. It
records 939 completed analyzer runs, 15 isolated Unicorn errors, and 318
explicit local IDA/Ghidra availability rows; angr and Triton complete every
configured pair. Binary Ninja was not measured in this historical run. The raw report
is [`protection-adversarial-corpus-2026-09-06-6de7999e-triton.json`](protection-adversarial-corpus-2026-09-06-6de7999e-triton.json)
(`SHA-256 d657735f230e396ffac78c5e95be702ba1db11032bb695c8649458ae4fd9288f`).

The authoritative rerun at `c0ceaaa6` repeats the CodeVirtualization corpus
against the current code. It records 159/159 applications, 171 virtualized
functions, zero unsupported functions, zero partial virtualizations, and zero
transformation errors. Triton and angr complete every original/protected pair;
the 15 tool errors are isolated to Unicorn AVX/VEX emulation, and the 318
unavailable rows are the local IDA/Ghidra executables. Binary Ninja was not
measured in this historical run. The raw report is
[`protection-adversarial-corpus-2026-09-06-c0ceaaa6-triton.json`](protection-adversarial-corpus-2026-09-06-c0ceaaa6-triton.json)
(`SHA-256 a6064409e3d7c3fe7b70cf04c255f34ccba7c4494b86dac1f12294526fd970dc`).

The current rerun at `aad4aeb9` repeats the same 159-fixture CodeVirtualization
corpus after closing the unwind-unsafe partial-virtualization path. It records
159/159 applications, 171 virtualized functions, zero unsupported functions,
zero partial virtualizations, and zero transformation errors. Triton and angr
complete every original/protected pair; the 15 tool errors remain isolated to
Unicorn AVX/VEX emulation, and the 318 unavailable rows are explicit local
IDA/Ghidra availability records. Binary Ninja was not measured in this historical run. The raw report is
[`protection-adversarial-corpus-2026-09-06-aad4aeb9-triton.json`](protection-adversarial-corpus-2026-09-06-aad4aeb9-triton.json)
(`SHA-256 73401f5d400d1490b8b013ac86c5c747c2b4e842ef8020bd8b33f0ef837b8698`).

The current rerun at `de3111e4` repeats the same 159-fixture CodeVirtualization
corpus after adding the disjoint-region unwind contract. It records 159/159
applications, 171 virtualized functions, zero unsupported functions, zero
partial virtualizations, and zero transformation errors. Triton and angr
complete every original/protected pair; the 15 tool errors remain isolated to
Unicorn AVX/VEX emulation, and the 318 unavailable rows are explicit local
IDA/Ghidra availability records. Binary Ninja was not measured in this historical run. The raw report is
[`protection-adversarial-corpus-2026-09-06-de3111e4.json`](protection-adversarial-corpus-2026-09-06-de3111e4.json)
(`SHA-256 feef3fbd2286fe4b8e15c32b720798f55c6ae2e86988ff423799096bc2294910`).

The current LSDA call-site mapping rerun at `a727f304` repeats the same
159-fixture CodeVirtualization corpus after preserving per-call-site unwind
metadata. It records 159/159 applications, 171 virtualized functions, zero
unsupported functions, zero partial virtualizations, and zero transformation
errors. Triton and angr complete every original/protected pair; the 15 tool
errors remain isolated to Unicorn AVX/VEX emulation, and the 318 unavailable
rows are explicit local IDA/Ghidra availability records. Binary Ninja was not
measured in this historical run. The raw report is
[`protection-adversarial-corpus-2026-09-06-a727f304.json`](protection-adversarial-corpus-2026-09-06-a727f304.json)
(`SHA-256 484f818c144ba58e418443d8e1dc9bed97de74586825f8cce8fe2e374c40b60a`).

The current-main all-pass host campaign at `2c9be637` adds fixture shard 14:
11 repository fixtures across all 22 declared passes (242 pass rows), with 30
applications, 212 no-ops, and no omitted or failed pass runs. Seven available
analyzers completed all 242 rows each. Binary Ninja was unavailable because
its license could not be used, and Triton was unavailable because the module
was not installed; these account for 484 of 2,178 expected analyzer runs.
angr reported unsupported dirty helpers, missing calling conventions, and
unhooked addresses. The hash-bound raw report and summary are
[`protection-host-adversarial-allpasses-2026-11-13-2c9be637-shard-14.json`](protection-host-adversarial-allpasses-2026-11-13-2c9be637-shard-14.json)
and
[`protection-host-adversarial-allpasses-2026-11-13-2c9be637-shard-14-summary.json`](protection-host-adversarial-allpasses-2026-11-13-2c9be637-shard-14-summary.json).
This is one repository-fixture shard; unavailable analyzers and bounded angr
results mean it does not complete the analyzer matrix or demonstrate general
resistance.

The next current-main host shard at `5806a27d` covered 10 repository fixtures
across all 22 passes (220 pass rows): 16 applications, 204 no-ops, zero
omissions, and zero pass errors. Six analyzers completed all rows; Unicorn
completed 198/220, while 22 runs were unavailable because its installed x86
emulator lacked an instruction used by a fixture. Binary Ninja and Triton
were unavailable for all 220 rows each (license and module availability,
respectively), so 462/1,980 analyzer runs were unavailable in total. angr
reported unsupported dirty helpers, unhooked addresses, and missing calling
conventions. The hash-bound reports are
[`protection-host-adversarial-allpasses-2026-11-13-5806a27d-shard-15.json`](protection-host-adversarial-allpasses-2026-11-13-5806a27d-shard-15.json)
and
[`protection-host-adversarial-allpasses-2026-11-13-5806a27d-shard-15-summary.json`](protection-host-adversarial-allpasses-2026-11-13-5806a27d-shard-15-summary.json).
This shard does not close the analyzer matrix or establish general resistance.

The current-main shard at `61f152e2` covered six repository fixtures across all
22 passes (132 rows): 12 applications, 120 no-ops, zero omissions, and zero
pass errors. Eight analyzers, including IDA Pro, Ghidra, and Triton, completed
all 132 rows. Binary Ninja was unavailable because the installed license was
invalid, leaving 132/1,188 analyzer slots unavailable. angr reported
unsupported VEX `IN`/`OUT` helpers, unhooked addresses, and missing inferred
calling conventions. Generated Linux fixtures were not included on macOS. The
hash-bound raw report and summary are
[`protection-host-adversarial-allpasses-2026-11-13-61f152e2-shard-16-32.json`](protection-host-adversarial-allpasses-2026-11-13-61f152e2-shard-16-32.json)
and
[`protection-host-adversarial-allpasses-2026-11-13-61f152e2-shard-16-32-summary.json`](protection-host-adversarial-allpasses-2026-11-13-61f152e2-shard-16-32-summary.json).
This bounded fixture slice does not establish general resistance or close the
all-analyzer criterion.

The next current-main slice at `b012cd0a` covers five repository fixtures across
all 22 passes (110 rows): 10 applications, 100 no-ops, zero omissions, and zero
pass errors. Eight analyzers completed all rows; Binary Ninja was unavailable
for all 110 rows because its license was unavailable. The generated Linux
fixtures were not part of this macOS run, and 16 passes had no application in
these five fixtures. The hash-bound raw report and summary are
[`protection-host-adversarial-allpasses-2026-11-13-b012cd0a-shard-17-32.json`](protection-host-adversarial-allpasses-2026-11-13-b012cd0a-shard-17-32.json)
and
[`protection-host-adversarial-allpasses-2026-11-13-b012cd0a-shard-17-32-summary.json`](protection-host-adversarial-allpasses-2026-11-13-b012cd0a-shard-17-32-summary.json).
This bounded sample does not close the analyzer matrix or establish general
resistance.

The scheduled 32-shard adversarial campaign then completed all 33 workflow jobs
in [run 43526206403](https://github.com/seifreed/r2morph/actions/runs/43526206403).
Its hash-bound summary and compressed merged report are
[`protection-adversarial-run-2026-11-14-43526206403.json`](protection-adversarial-run-2026-11-14-43526206403.json)
and
[`protection-adversarial-run-2026-11-14-43526206403.json.gz`](protection-adversarial-run-2026-11-14-43526206403.json.gz).
The campaign completed every pass row with zero pass errors, but only 77.04% of
analyzer runs completed: Binary Ninja and IDA Pro were unavailable and Unicorn
could not emulate 528 fixture instructions. Its VM resistance smoke remains
pending human adversarial review; these results do not establish general
resistance or cross-platform parity.
