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

Each build record includes the source digest, compiler command, toolchain
version, status, omission reason when applicable, compiler stdout/stderr
digests, elapsed time, and output size/hash. The public CI then transforms and
compares every built record independently for six selected passes:
BlockReordering, CodeVirtualization, InstructionExpansion,
InstructionSubstitution, NopInsertion, and RegisterSubstitution. It retains one
bounded matrix record per sample/pass pair and an aggregate result for each
pass.
Raw sample bytes and unbounded process output are not stored in reports. Each
transformation record includes the pass name, status (`applied`, `omitted`, or
`error`), and a bounded reason when the selected pass cannot transform the
sample.

The differential contract is original versus transformed execution across nine
seed-derived command-line inputs per sample: exit code, stdout, stderr, created
files, and declared observable effects must match. A failed comparison is a
release failure for the official Linux ELF x86-64 target.

The latest repository-fixture campaign against `3bfa94ed` covered 159 fixtures
and all six selected passes. Its per-pass summary is committed in
[`protection-maturity-by-pass-2026-09-04-3bfa94ed.json`](protection-maturity-by-pass-2026-09-04-3bfa94ed.json),
from workflow `33853083470` (artifact SHA-256
`616fa9ff55e0c89b498cb1abbddae8b4d51b15973a51c6a23090925ac53e3c0a`). All six
passes recorded 159 semantic passes with no failures. The corrected
`elf_vm_fppackedidxnb_x86_64` baseline and transformed binary both return 6 in
native and Unicorn execution.
The matching local adversarial report is summarized in
[`protection-adversarial-corpus-2026-09-04-3bfa94ed-summary.json`](protection-adversarial-corpus-2026-09-04-3bfa94ed-summary.json)
(raw report SHA-256
`4aff53dffa249d2ee793ee02c203a415c537f1cb157cfb9ff97685633e763a63`). IDA Pro,
Triton, and angr each completed all 159 original/protected pairs with zero
analyzer errors. CodeVirtualization applied to all samples, virtualized 171
functions, reported five explicitly unsupported functions, and had zero
transformation errors.
The latest local Ghidra headless campaign for the 159-fixture corpus at
`88258a05` completed 318 analyses with zero errors or timeouts. Its raw report is
[`protection-ghidra-corpus-2026-09-04-88258a05.json`](protection-ghidra-corpus-2026-09-04-88258a05.json),
with the per-run contract in
[`protection-ghidra-corpus-2026-09-04-88258a05-summary.json`](protection-ghidra-corpus-2026-09-04-88258a05-summary.json)
and SHA-256
`cd86ada75b515f84676bb110807cf8d964276cb5bda54831750aec70d28c5f25`.

The corpus workflow also runs a bounded static-recovery benchmark with
`radare2` over every passed original/transformed pair and pass, recording
function, basic-block, edge, instruction, and duration deltas without retaining
analyzer output. The current six-pass transformation, differential-execution,
static-recovery, and malformed-input run is tracked in
[`33259963329`](https://github.com/seifreed/r2morph-corpus/actions/runs/33259963329).
The corresponding full Ghidra headless run is tracked in
[`33259983358`](https://github.com/seifreed/r2morph-corpus/actions/runs/33259983358).
IDA Pro, angr, and Triton now have complete local repository-fixture runs.
Licensed local measurements remain separate from public-runner evidence.
