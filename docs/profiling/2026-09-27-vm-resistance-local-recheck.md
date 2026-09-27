# VM resistance local recheck

## Scope

The ten tracked ELF x86-64 resistance fixtures were re-run locally with ten
seeds (`20260820` through `20260829`). The generated Linux-only fixtures were
not included because this host does not provide the required Linux x86-64
toolchain; the complete 15-fixture campaign remains covered by the Linux CI
artifact `protection-vm-resistance-2026-09-22-e3a491b3.json`.

## Result

The local report completed with semantic parity, distinct artifacts, opcode,
dispatcher, handler, bytecode grammar, and bounded recovery checks all true.
Native ELF execution was unavailable on macOS, so this run is a recheck of
the automated resistance invariants, not a replacement for the full Linux
campaign or external human signoff.
