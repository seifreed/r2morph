# Compatibility Corpus

The public, reproducible corpus is maintained in
[`seifreed/r2morph-corpus`](https://github.com/seifreed/r2morph-corpus), currently
pinned to commit
[`078deac`](https://github.com/seifreed/r2morph-corpus/commit/078deac8bd72d37f2309ec61e5f3d84685459af4).
It contains source programs, the build matrix, SHA-256 manifests, differential
execution records, and static-recovery benchmark results. The project
repository does not embed generated binaries.

The matrix covers GCC and Clang, `-O0`, `-O1`, `-O2`, `-O3`, and `-Os`, PIE and
non-PIE, symbol-preserving and stripped outputs, dynamic linking, and static
linking when the host toolchain provides it. C and C++ fixtures exercise switch
dispatch, loops, recursion, pointers, TLS, and C++ exceptions.

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
campaign triage.
The adversarial benchmark also measures Binary Ninja through its installed API
when a licensed installation is available; otherwise its row is explicitly
reported as unavailable rather than omitted.
Corpus benchmark reports also aggregate completed, unavailable, error, changed,
bounded unavailable/error reasons, duration pair counts and totals, comparable
numeric metric pair counts, and numeric original-versus-protected metric deltas
per analyzer so campaigns remain comparable by tool. Their top-level summary
also records expected versus observed pass/tool counts and run counts for
campaign coverage, including coverage percentages, missing names, and
applied/omitted/error pass rates, counts, and reasons, per-pass/per-tool run
counts, plus completed/unavailable/error tool rates, counts, and reasons by
analyzer, completed-tool coverage over expected pass/tool slots, and
non-completed-tool gaps by analyzer.
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
The adversarial campaign summary records distinct completed, unavailable, and
errored analyzer tools, so completed `angr` or Triton runs are not hidden behind
environment-specific IDA, Ghidra, or Binary Ninja availability gaps. It also
records completed-run coverage by analyzer tool so campaigns remain comparable
when a licensed or local analyzer is missing.

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
`elf_vm_fppackedidxnb_x86_64`. Binary Ninja is explicitly omitted. The raw
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
are the local IDA/Ghidra executables. Binary Ninja is intentionally omitted.
The raw report is
[`protection-adversarial-corpus-2026-09-05-44bca563-triton.json`](protection-adversarial-corpus-2026-09-05-44bca563-triton.json).

The latest rerun at `a92e8b9` repeats all 159 fixtures and six passes after the
carry-control flag semantics update. It records 159/159 CodeVirtualization
applications, 171 virtualized functions, and zero unsupported functions.
Triton and angr complete every configured pair; the 47 errors remain isolated
to Unicorn, and the 1,908 unavailable rows remain the local IDA/Ghidra
executables. Binary Ninja is intentionally omitted. The raw report is
[`protection-adversarial-corpus-2026-09-05-a92e8b9-triton.json`](protection-adversarial-corpus-2026-09-05-a92e8b9-triton.json).

This `fa85d18` rerun repeats the same corpus after adding native `neg` flag
semantics. It records 159/159 CodeVirtualization applications, 171 virtualized
functions, and zero unsupported functions. Triton and angr complete every
configured pair; the 47 errors remain isolated to Unicorn, and the 1,908
unavailable rows remain the local IDA/Ghidra executables. Binary Ninja remains
intentionally omitted. The raw report is
[`protection-adversarial-corpus-2026-09-05-fa85d18-triton.json`](protection-adversarial-corpus-2026-09-05-fa85d18-triton.json).

The current `c820685f` rerun repeats the CodeVirtualization corpus after the
memory-destination carry semantics update. It records 159/159 applications,
171 virtualized functions, and zero unsupported functions. Triton and angr
complete all 159 original/protected pairs; 15 `UcError` rows are isolated to
Unicorn AVX/VEX emulation. IDA and Ghidra are explicitly unavailable in this
macOS run (318 rows), and Binary Ninja remains omitted by project decision.
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

The authoritative current CodeVirtualization rerun at `dbf77c59` repeats all
159 repository fixtures with the dedicated Python 3.13 virtualenv containing
`triton-library 1.0.0rc4`. It records 159/159 applications, 171 virtualized
functions, zero unsupported functions, and zero transformation errors. Triton
and angr complete every original/protected pair. The 15 tool errors are
isolated to Unicorn AVX/VEX emulation, and the 318 unavailable rows are the
local IDA/Ghidra executables. Binary Ninja is intentionally omitted. The raw
report is
[`protection-adversarial-corpus-2026-09-06-dbf77c59-triton.json`](protection-adversarial-corpus-2026-09-06-dbf77c59-triton.json)
(`SHA-256 22410aa82448504a28964b9fa9e436a6014c8d2545f9adf9653f9c9a39ceecea`).

The current rerun at `76e144bb` repeats the same 159-fixture
CodeVirtualization campaign with the dedicated Python 3.13 virtualenv. It
records 159/159 applications, 171 virtualized functions, zero unsupported
functions, and zero partial virtualizations. Angr and Triton complete every
original/protected pair; the 15 tool errors are isolated to Unicorn, and the
318 unavailable rows are the local IDA/Ghidra executables. Binary Ninja is
intentionally omitted. The named `elf_vm_fppackedidxnb_x86_64` regression
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
executables. Binary Ninja is intentionally omitted. The raw report is
[`protection-adversarial-corpus-2026-09-06-51b949a-triton.json`](protection-adversarial-corpus-2026-09-06-51b949a-triton.json)
(`SHA-256 f2cab32b9608a5490233b8b1f83c85f6f23f6ff45d66f907150a8ab8d6d29f11`).

The current rerun at `d82cc2b9` repeats the same 159-fixture CodeVirtualization
campaign with `triton-library 1.0.0rc4` in the Python 3.13 virtualenv. It
records 159/159 applications, 171 virtualized functions, zero unsupported
functions, zero partial virtualizations, and zero transformation errors. Angr
and Triton complete every original/protected pair; the 15 tool errors remain
isolated to Unicorn, while the 318 unavailable rows are the local IDA/Ghidra
executables. Binary Ninja is intentionally omitted. The named
`elf_vm_fppackedidxnb_x86_64` regression virtualizes one function and preserves
exit code 6. The raw report is
[`protection-adversarial-corpus-2026-09-06-d82cc2b9-triton.json`](protection-adversarial-corpus-2026-09-06-d82cc2b9-triton.json)
(`SHA-256 f004d1c2c33e7484b93c52cee3357927bf27215ea221419819bfc43785f5f920`).

The focused IDA validation at `702450d7` covers the corrected
`elf_vm_fppackedidxnb_x86_64` regression. Original and protected execution
both return 6; IDA completes with 1 and 2 recovered functions respectively,
with zero errors. Angr and Triton also complete both binaries. The bounded
record is [`protection-fppackedidxnb-ida-2026-09-06-702450d7.json`](protection-fppackedidxnb-ida-2026-09-06-702450d7.json).
Binary Ninja remains intentionally omitted.

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
rows are explicit local IDA/Ghidra availability records. Binary Ninja remains
intentionally omitted. The raw report is
[`protection-adversarial-corpus-2026-09-06-bc2bff2.json`](protection-adversarial-corpus-2026-09-06-bc2bff2.json)
(`SHA-256 7c673f5cf52d7b6ee564b6a3d6aab59d7436af0e6f4590b27705db439ad031fc`),
with the bounded summary in
[`protection-adversarial-corpus-2026-09-06-bc2bff2-summary.json`](protection-adversarial-corpus-2026-09-06-bc2bff2-summary.json).

The current rerun at `43ba227c` repeats the same 159-fixture
CodeVirtualization corpus after scoping the unwind gate to the candidate VM
region. It records 159/159 applications, 171 virtualized functions, zero
unsupported functions, zero partial virtualizations, 939 completed analyzer
runs, 15 isolated Unicorn errors, and 318 explicit local IDA/Ghidra
availability rows. Angr and Triton complete every configured pair; Binary
Ninja remains intentionally omitted. The raw report is
[`protection-adversarial-corpus-2026-09-06-43ba227c.json`](protection-adversarial-corpus-2026-09-06-43ba227c.json)
(`SHA-256 83b90d71cc4db022ef81634e87d327279da71513984108a42dae3beb3b319d5c`),
with the bounded summary in
[`protection-adversarial-corpus-2026-09-06-43ba227c-summary.json`](protection-adversarial-corpus-2026-09-06-43ba227c-summary.json).

The post-unwind-metadata rerun at `6de7999e` repeats the same 159-fixture
CodeVirtualization corpus with 159/159 applications, 171 virtualized
functions, zero unsupported functions, and zero partial virtualizations. It
records 939 completed analyzer runs, 15 isolated Unicorn errors, and 318
explicit local IDA/Ghidra availability rows; angr and Triton complete every
configured pair. Binary Ninja remains intentionally omitted. The raw report
is [`protection-adversarial-corpus-2026-09-06-6de7999e-triton.json`](protection-adversarial-corpus-2026-09-06-6de7999e-triton.json)
(`SHA-256 d657735f230e396ffac78c5e95be702ba1db11032bb695c8649458ae4fd9288f`).

The authoritative rerun at `c0ceaaa6` repeats the CodeVirtualization corpus
against the current code. It records 159/159 applications, 171 virtualized
functions, zero unsupported functions, zero partial virtualizations, and zero
transformation errors. Triton and angr complete every original/protected pair;
the 15 tool errors are isolated to Unicorn AVX/VEX emulation, and the 318
unavailable rows are the local IDA/Ghidra executables. Binary Ninja remains
omitted by project decision. The raw report is
[`protection-adversarial-corpus-2026-09-06-c0ceaaa6-triton.json`](protection-adversarial-corpus-2026-09-06-c0ceaaa6-triton.json)
(`SHA-256 a6064409e3d7c3fe7b70cf04c255f34ccba7c4494b86dac1f12294526fd970dc`).

The current rerun at `aad4aeb9` repeats the same 159-fixture CodeVirtualization
corpus after closing the unwind-unsafe partial-virtualization path. It records
159/159 applications, 171 virtualized functions, zero unsupported functions,
zero partial virtualizations, and zero transformation errors. Triton and angr
complete every original/protected pair; the 15 tool errors remain isolated to
Unicorn AVX/VEX emulation, and the 318 unavailable rows are explicit local
IDA/Ghidra availability records. Binary Ninja remains omitted by project
decision. The raw report is
[`protection-adversarial-corpus-2026-09-06-aad4aeb9-triton.json`](protection-adversarial-corpus-2026-09-06-aad4aeb9-triton.json)
(`SHA-256 73401f5d400d1490b8b013ac86c5c747c2b4e842ef8020bd8b33f0ef837b8698`).

The current rerun at `de3111e4` repeats the same 159-fixture CodeVirtualization
corpus after adding the disjoint-region unwind contract. It records 159/159
applications, 171 virtualized functions, zero unsupported functions, zero
partial virtualizations, and zero transformation errors. Triton and angr
complete every original/protected pair; the 15 tool errors remain isolated to
Unicorn AVX/VEX emulation, and the 318 unavailable rows are explicit local
IDA/Ghidra availability records. Binary Ninja remains omitted by project
decision. The raw report is
[`protection-adversarial-corpus-2026-09-06-de3111e4.json`](protection-adversarial-corpus-2026-09-06-de3111e4.json)
(`SHA-256 feef3fbd2286fe4b8e15c32b720798f55c6ae2e86988ff423799096bc2294910`).

The current LSDA call-site mapping rerun at `a727f304` repeats the same
159-fixture CodeVirtualization corpus after preserving per-call-site unwind
metadata. It records 159/159 applications, 171 virtualized functions, zero
unsupported functions, zero partial virtualizations, and zero transformation
errors. Triton and angr complete every original/protected pair; the 15 tool
errors remain isolated to Unicorn AVX/VEX emulation, and the 318 unavailable
rows are explicit local IDA/Ghidra availability records. Binary Ninja remains
omitted by project decision. The raw report is
[`protection-adversarial-corpus-2026-09-06-a727f304.json`](protection-adversarial-corpus-2026-09-06-a727f304.json)
(`SHA-256 484f818c144ba58e418443d8e1dc9bed97de74586825f8cce8fe2e374c40b60a`).
