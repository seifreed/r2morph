# Adversarial Benchmark Profiling

## Scope

The benchmark measured the same fixture with one and two mutation passes while
Ghidra, angr, radare2, and the remaining configured analyzer slots were active.
The original binary was analyzed once per pass before this change.

## Before

Fixture: `elf_vm_shift_x86_64`

| Pass | Real time |
|---|---:|
| `CodeVirtualization` | 16.44 s |
| `NopInsertion` | 11.66 s |
| Sequential total | 28.10 s |

The CodeVirtualization pair spent approximately 5.79 s on the original Ghidra
analysis and 5.23 s on the protected binary. Repeating the original analysis
for every pass was redundant because the input fixture is unchanged.

## Change and result

`benchmark_pair` now retains completed original-tool metrics for the lifetime
of one fixture and reuses them for subsequent passes. The two-pass campaign
then measured 19.50 s real time, a 30.6% reduction against the sequential
baseline. Protected binaries are still analyzed independently for every pass.

The cache is bounded to the configured analyzer slots for one fixture and is
discarded before the next fixture, so it does not retain corpus payloads.
