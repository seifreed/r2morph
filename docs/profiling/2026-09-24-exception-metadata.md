# Exception metadata query profile

## Scope

This profile covers the public C++ exception corpus shape that previously
timed out in `CodeVirtualization` for statically linked optimized ELF files.
The change caches section metadata during one exception-frame read and limits
protected-callee disassembly to functions covered by an LSDA frame.

## Measurements

| Revision | Fixture | Result | Wall time |
|---|---|---|---:|
| `a248ad6` | GCC O3, static, Linux container | transformation omitted after analysis-budget handling | ~71 s |
| `a248ad6` | Public GCC/Clang O3 static corpus | `TimeoutExpired` at 120 s | 120 s cap |
| `923f53c` | GCC O3, static, same Linux container | transformation omitted after analysis-budget handling | 31 s |

The post-change run produced an unchanged output with status `omitted` and
reason `analysis_budget: function population exceeds the VM analysis budget`.
The O0 dynamic C++ exception fixture returned exit code `99` before and after
virtualization. The section-cache regression reports one section query for a
complete ELF exception-frame parse.

## Interpretation

The measured hot path was radare2 analysis followed by repeated `iSj` section
queries while parsing `.eh_frame`/LSDA and disassembling every function for
protected callees. The change reduces redundant metadata queries and avoids
unrelated disassembly without weakening the exact LSDA call-site check.

The public GitHub differential campaign for `923f53c` remains the authoritative
cross-tool confirmation; this local profile does not replace it.
