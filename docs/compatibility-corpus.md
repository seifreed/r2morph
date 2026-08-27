# Compatibility Corpus

The public, reproducible corpus is maintained in
[`seifreed/r2morph-corpus`](https://github.com/seifreed/r2morph-corpus), currently
pinned to commit
[`8267a92`](https://github.com/seifreed/r2morph-corpus/commit/8267a9234a61939c7c3ef5514983fbd9285d41a0).
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
compares every built record, retaining one bounded matrix record per sample.
Raw sample bytes and unbounded process output are not stored in reports. Each
transformation record includes the pass name, status (`applied`, `omitted`, or
`error`), and a bounded reason when the selected pass cannot transform the
sample.

The differential contract is original versus transformed execution across five
seed-derived command-line inputs per sample: exit code, stdout, stderr, created
files, and declared observable effects must match. A failed comparison is a
release failure for the official Linux ELF x86-64 target.

The corpus workflow also runs a bounded static-recovery benchmark with
`radare2` over every passed original/transformed pair, recording function,
basic-block, edge, instruction, and duration deltas without retaining analyzer
output. The public run
[`33030578544`](https://github.com/seifreed/r2morph-corpus/actions/runs/33030578544)
passed with `160/160` measured samples. IDA Pro, Ghidra, Binary Ninja, angr, and
Triton remain explicit omissions until public runners are configured. The
current workflow also generates six deterministic malformed ELF inputs and
requires the real parser to reject all six; its current run is pending runner
allocation.
