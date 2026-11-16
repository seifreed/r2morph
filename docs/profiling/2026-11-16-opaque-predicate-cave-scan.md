# Opaque predicate cave-scan profiling

## Scope

The adversarial workflow reported a 180-second mutation-worker timeout for
`OpaquePredicates` on the generated static C++ exception fixture. The workflow
artifact recorded the sample name but did not include its original bytes. The
local fixture below was rebuilt from the checked-in generator with the same
Clang profile; its hash is recorded so this result is reproducible, but it is
not claimed to be byte-identical to the unavailable workflow sample.

## Fixture and environment

- Platform: Ubuntu 24.04, Linux x86-64
- Python: 3.12.3
- radare2: 6.2.2, built by `.github/scripts/install_radare2.sh`
- Fixture: `generated_cpp_exceptions_clangxx-static-o2`
- Fixture SHA-256: `5fa4463ab3b4eb5862269893a9bad0c0ec94d345791ba30ffe89c0cb9dd84f3c`
- Source baseline: `da76fbb4d2c73b57320e5385a5a6628ba05c4f9b`
- Operation: `scripts.adversarial_benchmark_tools._protected_copy_worker` with
  the `OpaquePredicates` pass; both runs completed with `no-op` and zero
  mutations, so the comparison measures the same outcome.

## Profile results

| Measurement | Before | After | Change |
|---|---:|---:|---:|
| Worker wall time | 110.569 s | 49.307 s | -55.4% |
| `CaveFinder.find_caves` cumulative time | 90.409 s | 12.213 s | -86.5% |
| `Binary.get_function_disasm` calls | 40,614 | 1,806 | -95.6% |

Before the change, each of 23 cave searches repeated the executable-function
disassembly scan. The post-change profile computes instruction ranges once for
the pass-local injector and reuses that snapshot across its cave searches. The
general `CaveFinder` default remains uncached because callers may change the
binary between queries.

The one remaining `CaveFinder._instruction_ranges` call took 9.144 seconds in
the post-change profile. Other costs now dominate, including binary analysis
and per-function liveness; this change does not claim to make the pass fast for
all binaries. The local timing is below the 180-second worker limit, but CI
must still confirm the result on its runner and generated fixture.

The post-change worker profile took 49.307 seconds; a preceding repeat measured
41.776 seconds. Runner load affects wall time, so the call-count and cumulative
profile deltas are the stronger indicators of the change.
