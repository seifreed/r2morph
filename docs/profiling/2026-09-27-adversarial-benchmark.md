# Adversarial Benchmark Baseline

## Scope

- Commit: `5cbe1d43`
- Fixture: `fixtures/dataset/elf_nop_x86_64`
- Pass selection: all 22 corpus and extended maturity passes
- Run date: 2026-09-27

## Local Measurement

Command:

```text
python3 scripts/adversarial_benchmark.py fixtures/dataset/elf_nop_x86_64 --passes all
```

Wall-clock duration was 18.89 seconds. The report recorded 22 completed rows
for each locally available analyzer: radare2, objdump, angr, Unicorn, and the
custom analyzer. `angr` supplied 22 complete decompiler pairs and took 4.52
seconds in aggregate. Binary Ninja recorded 22 explicit unavailable rows
because no license was available; it was not treated as a completed analyzer.

The local environment did not provide the scheduled Ghidra installation, so
this result is a local baseline only. It does not replace the GitHub campaign,
which is the authoritative source for comparable Ghidra evidence.

## Interpretation

The measurement establishes a per-fixture baseline for the current sequential
analyzer path. It is insufficient by itself to justify a performance change:
the remote campaign must finish before comparing its Ghidra-inclusive runtime.
