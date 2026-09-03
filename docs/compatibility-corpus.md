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

The latest repository-fixture campaign against `7c3d9e5` covered 148 fixtures
and all six selected passes. Its per-pass summary is committed in
[`protection-maturity-by-pass-2026-09-03-7c3d9e5.json`](protection-maturity-by-pass-2026-09-03-7c3d9e5.json),
from workflow `33704362906` (artifact SHA-256
`bd9e8b57a80c5099462c72b67c692c35f67d65ca78a05e33ca91eaf0b4b8ac7a`). The
matching adversarial report is summarized in
[`protection-adversarial-corpus-2026-09-03-7c3d9e5-summary.json`](protection-adversarial-corpus-2026-09-03-7c3d9e5-summary.json),
from workflow `33704363064` (artifact SHA-256
`f96221084edddcc01a83110bc19a5ce22a20785750213a9502b3b2c0bc0220cb`).
The local Ghidra headless campaign for the same 148-fixture corpus completed
296 analyses with zero errors or timeouts. Its raw report is
[`protection-ghidra-corpus.json`](protection-ghidra-corpus.json), with the
per-run contract in
[`protection-ghidra-corpus-2026-09-03-7c3d9e5-summary.json`](protection-ghidra-corpus-2026-09-03-7c3d9e5-summary.json)
and SHA-256
`59b4f1360dc36cfbb618b6ddcaf9447d34acd0247f2ec5117091af9d8280e17f`.

The corpus workflow also runs a bounded static-recovery benchmark with
`radare2` over every passed original/transformed pair and pass, recording
function, basic-block, edge, instruction, and duration deltas without retaining
analyzer output. The current six-pass transformation, differential-execution,
static-recovery, and malformed-input run is tracked in
[`33259963329`](https://github.com/seifreed/r2morph-corpus/actions/runs/33259963329).
The corresponding full Ghidra headless run is tracked in
[`33259983358`](https://github.com/seifreed/r2morph-corpus/actions/runs/33259983358).
IDA Pro, Binary Ninja, angr, and Triton remain explicit omissions until public
runners are configured. Final per-pass metrics are published as workflow
artifacts only after both runs complete.
