# Liveness alias-cache profile

## Question

The adversarial benchmark timed out on `generated_cpp_exceptions_clangxx-static-o2`
while running `OpaquePredicates`. Profiling showed repeated construction of
register alias sets in `LivenessAnalysis._build_interference_graph`. Cache those
sets once per distinct register within the analysis call and compare the exact
benchmark worker before and after.

## Method

- Input: the generated C++ exception fixture
  `generated_cpp_exceptions_clangxx-static-o2`, compiled as a static x86-64 ELF
  with Clang 18 and `-O2`.
- Worker: `scripts.adversarial_benchmark_tools._protected_copy_worker`, pass
  `OpaquePredicates`, seed `20260827`.
- Before: commit `b2c44786`, which includes the liveness characterization test
  but not the alias cache.
- After: the working tree containing the alias-cache change.
- Host: macOS ARM64, Python 3.14.10, radare2 6.2.6; the input is x86-64 and is
  analyzed by radare2 rather than executed natively.
- Measurement: Python `cProfile` around the worker. The full pytest suite was
  running concurrently, so wall-clock numbers are directional and should not
  be compared with CI timings. Both runs used the same host, input, pass, and
  seed.

## Results

| Measurement | Before | After | Change |
| --- | ---: | ---: | ---: |
| Worker cumulative time | 22.405 s | 10.151 s | -54.7% |
| `OpaquePredicates.apply` cumulative time | 20.044 s | 7.817 s | -61.0% |
| `_build_interference_graph` cumulative time | 9.591 s | 1.071 s | -88.8% |
| `Register.aliases()` calls | 3,123,760 | 634,008 | -79.7% |
| Mutations applied | 13 | 13 | unchanged |
| Output | 992,064 bytes; SHA-256 `67b3f6ab6ea017381dde85a13090d6fefe95ba4868ac98dea2aff1a5d87c2d45` | Same size and SHA-256 | byte-identical |

The optimization addresses a dominant measured cost: the interference graph
spent 9.59 seconds of 20.04 seconds in the mutation pass before the change.
Both runs applied the same number of mutations and produced the same output
size. The generated files are byte-identical for this input and seed, which is
stronger than comparing size but still covers only this one fixture.

After the CI timeout was observed, the current worker was run four more times
without a profiler on the same retained input. All four runs applied 13
mutations and produced the same SHA-256 above; elapsed times were 11.910,
26.757, 10.878, and 13.085 seconds. The unprofiled runs used Python 3.14.10,
radare2 6.2.6, and the macOS ARM64 host. The input SHA-256 was
`5fa4463ab3b4eb5862269893a9bad0c0ec94d345791ba30ffe89c0cb9dd84f3c`.

## Validation limits

This is a local directional profile, not a supported-runtime or production
benchmark: Python 3.14.10 is outside the declared supported range, the host is
macOS ARM64, and the suite competed for CPU. The Linux x86-64 adversarial
benchmark and supported-version CI remain the authoritative validation for
whether the timeout is resolved. The measured local variation does not explain
the 180-second Linux timeout. Do not use this profile alone to claim the
benchmark timeout is fixed.
