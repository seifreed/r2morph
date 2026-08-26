# Compatibility Corpus

The public, reproducible corpus is maintained in
[`seifreed/r2morph-corpus`](https://github.com/seifreed/r2morph-corpus). It
contains source programs, the build matrix, SHA-256 manifests, and differential
execution records. The project repository does not embed generated binaries.

The matrix covers GCC and Clang, `-O0`, `-O1`, `-O2`, `-O3`, and `-Os`, PIE and
non-PIE, symbol-preserving and stripped outputs, dynamic linking, and static
linking when the host toolchain provides it. C and C++ fixtures exercise switch
dispatch, loops, recursion, pointers, TLS, and C++ exceptions.

Each record includes the source digest, compiler command, toolchain version,
format, architecture, transformation, omission reason when applicable, exit
status, stdout/stderr digests, created-file manifest, elapsed time, and size
change. Raw sample bytes and unbounded process output are not stored in reports.
The local maturity runner stores transformation evidence as `pass_name`,
`status` (`applied`, `omitted`, or `error`), and a bounded `reason` when the
selected pass cannot transform the sample.

The differential contract is original versus transformed execution: exit code,
stdout, stderr, created files, and declared observable effects must match. A
failed comparison is a release failure for the official Linux ELF x86-64 target.
