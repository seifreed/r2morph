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

The latest repository-fixture campaign against `47992a5` covered 158 fixtures
and all six selected passes. Its per-pass summary is committed in
[`protection-maturity-by-pass-2026-09-04-47992a5.json`](protection-maturity-by-pass-2026-09-04-47992a5.json),
from workflow `33841892183` (artifact SHA-256
`fffa73d4ab32f7d6f721e0937578b50a50f8af3a787c30525ed5a39a8e35f263`). Five
passes recorded 158 semantic passes with no failures; CodeVirtualization
recorded 157 semantic passes and one known baseline mismatch in
`elf_vm_fppackedidxnb_x86_64`. The mismatch remains a baseline runtime
contract issue with zero mutations applied, not a new transformation failure.
The matching adversarial report is summarized
in
[`protection-adversarial-corpus-2026-09-04-47992a5-summary.json`](protection-adversarial-corpus-2026-09-04-47992a5-summary.json),
from workflow `33841894143` (artifact SHA-256
`bb400440363c58678518e14c01c6f1dcb3a82fda57eb00957c4e66c788abbddb`). It
covered 158 samples and 4,697 completed tool runs, with 3,792 unavailable
tool rows and 43 tool errors; CodeVirtualization applied to all samples and
virtualized 169 functions with no unsupported functions or transformation
errors.
The latest local Ghidra headless campaign for the 158-fixture corpus at
`4eecb48d` completed
316 analyses with zero errors or timeouts. Its raw report is
[`protection-ghidra-corpus-2026-09-04-4eecb48.json`](protection-ghidra-corpus-2026-09-04-4eecb48.json),
with the per-run contract in
[`protection-ghidra-corpus-2026-09-04-4eecb48-summary.json`](protection-ghidra-corpus-2026-09-04-4eecb48-summary.json)
and SHA-256
`cf084dc070bc29158bf3c6baf30b57b08b1707ca1156e420401b8f470030600f`.

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
