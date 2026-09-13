# Pass Maturity Contract

The release contract is per-pass. A pass is Tier 1 only when native tests,
runtime validation, and the compatibility corpus cover the official Linux ELF
x86-64 target. Every other entry remains experimental until its evidence is
promoted.
Preview PE, Mach-O, ARM, and AArch64 evidence does not imply parity with the
official Linux ELF x86-64 target.

The compatibility corpus selection currently covers `BlockReordering`,
`CodeVirtualization`, `ConstantUnfolding`, `ControlFlowFlattening`,
`DeadCodeInjection`, `InstructionExpansion`, `InstructionSubstitution`,
`NopInsertion`, `PatternSubstitution`, and `RegisterSubstitution`.

| Pass | Status | Target | Current limitation | Evidence |
|---|---|---|---|---|
| NOP insertion | Tier 1 | Linux ELF x86-64; PE x86-64 and Mach-O x86-64/AArch64 preview | Preview targets require real structural validation and checksum/signature handling; no official cross-platform contract | `tests/product_smoke`, `tests/integration`, `tests/integration/test_nop_insertion_pe_real.py`, `tests/integration/test_mutation_nop_insertion_arm64.py`, `tests/integration/test_mutations_x86_compiled_binary.py` |
| Instruction substitution | Tier 1 | Linux ELF x86-64; PE x86-64 and Mach-O AArch64 preview | Rule coverage is ISA-specific; preview evidence covers one real PE fixture and direct 12-bit ARM64 move-immediate substitutions | `tests/product_smoke`, `tests/integration`, `tests/integration/test_mutation_nop_insertion_arm64.py`, `tests/integration/test_mutation_passes_end_to_end_more2.py` |
| Register substitution | Tier 1 | Linux ELF x86-64; PE x86-64 and Mach-O AArch64 preview | Requires proven liveness and ABI preservation; non-ELF targets remain experimental | `tests/product_smoke`, `tests/integration`, `tests/integration/test_nop_insertion_pe_real.py`, `tests/integration/test_mutation_register_substitution_arm64.py` |
| Instruction expansion | Experimental | ELF x86-64 | Selected by the compatibility corpus; wider replacements still need cross-platform evidence and analyzer-effectiveness results | `README.md`, `docs/compatibility-corpus.md` |
| Block reordering | Experimental | ELF x86-64 | Selected by the compatibility corpus; complex indirect control flow is rejected | `tests/integration`, `docs/compatibility-corpus.md` |
| Dead code injection | Experimental | ELF x86-64 | Selected by the compatibility corpus; placement depends on available safe regions and analyzer-effectiveness evidence remains incomplete | `tests/integration/test_dead_code_injection_flag_safe_real.py`, `tests/integration/test_protection_maturity_baseline.py`, `docs/compatibility-corpus.md` |
| Control-flow flattening | Experimental | ELF x86-64 | Selected by the compatibility corpus; cross-tool decompiler benchmark and composition evidence remain incomplete | `tests/integration/test_control_flow_flattening_flag_safe_real.py`, `tests/integration/test_protection_maturity_baseline.py`, `docs/compatibility-corpus.md` |
| Opaque predicates | Experimental | ELF x86-64 | Predicate families are not exhaustive | `README.md` |
| Code virtualization | Experimental | ELF x86-64 | Selected by the compatibility corpus; unsupported functions are rejected or conservatively unchanged with diagnostics | `docs/protection-maturity.md`, `docs/compatibility-corpus.md`, `tests/integration/test_code_virtualization_generic_isa_real.py` |
| Anti-disassembly | Experimental | ELF x86-64 | No independent review evidence | `README.md` |
| Data-flow mutation | Experimental | ELF x86-64 | Narrow instruction family | `README.md` |
| Short-jump patching | Experimental | ELF x86-64 | Needs more relocation coverage | `README.md` |
| Constant unfolding | Experimental | ELF x86-64 | Selected by the compatibility corpus; x86-only transformation rules and analyzer-effectiveness evidence remain incomplete | `tests/integration/test_protection_maturity_baseline.py`, `fixtures/dataset/elf_constant_unfold_x86_64.S`, `docs/compatibility-corpus.md` |
| Code mobility | Experimental | ELF x86-64 | Code-cave geometry is input-dependent | `README.md` |
| Function outlining | Experimental | ELF x86-64 | ABI and exception edges need more evidence | `README.md` |
| API hashing | Experimental | ELF x86-64 | External symbol behavior is environment-dependent | `README.md` |
| Import obfuscation | Experimental | ELF x86-64 | Format-specific import handling | `README.md` |
| Self-modifying code | Experimental | ELF x86-64 | Runtime validation is mandatory and limited | `README.md` |
| Stack strings | Experimental | ELF x86-64 | String layout and ABI interactions need more corpus coverage | `README.md` |
| String obfuscation | Experimental | ELF x86-64 | Runtime string reconstruction is environment-dependent | `README.md` |
| Pattern substitution | Experimental | ELF x86-64 | Selected by the compatibility corpus; pattern coverage is intentionally narrow and composition evidence remains incomplete | `README.md`, `docs/compatibility-corpus.md` |
| Polymorphic engine | Experimental | ELF x86-64 | Pipeline composition requires per-pass validation | `README.md` |

The machine-readable format and evidence paths are in
[`support-matrix.json`](support-matrix.json). A pass cannot be promoted by a
single fixture or a static disassembly result alone.
The generated matrix summary records evidenced versus not-supported cells,
including official and non-official targets, so the Linux ELF x86-64 baseline
and PE, Mach-O, ARM, and AArch64 parity gaps are visible without expanding every
cell. It also records evidence percentages for official and non-official targets
so preview coverage cannot look equivalent to the supported baseline. The
current matrix records 100.0% official evidence, 2.89% non-official evidence,
7 non-official evidenced cells, and 235 non-official not-supported cells. It
also lists 11 non-official format/architecture targets in
`non_official_gap_targets`; only Mach-O AArch64, Mach-O x86-64, and PE x86-64
currently have any preview evidence, while ELF AArch64/ARM/x86, Mach-O ARM/x86,
and PE AArch64/ARM/x86 remain at 0.0% evidence. It
also counts passes per declared
stability and maturity profile so Tier 1, corpus-selected,
code-virtualization, and experimental coverage remain visible at release-gate
level: 3 tier-1 passes, 19 experimental passes, 3 tier-1-native profile passes,
6 experimental-corpus-selected profile passes, 1 code-virtualization profile
pass, and 12 experimental profile passes. It also summarizes the declared
performance, false-positive-risk,
instructions-affected, decompiler-effectiveness, and compatibility/composition
text by profile so unmeasured cost, ISA coverage, risk, analyzer effectiveness,
and pass-composition gaps remain visible release gaps instead of being buried in
each pass row.
The current summary still reports 12 passes with no per-pass performance
measurement, 12 with no independent false-positive measurement, 15 with no
independent decompiler-effectiveness measurement, 12 without contractual
composition support, and 18 without an exhaustive affected-instruction
catalogue. The generated matrix also names the affected passes in
`maturity_gap_passes`, so per-pass maturity gaps are reviewable without
reconstructing them from profile text.
Runtime support classification also exposes `parity_gap` and
`parity_gap_scope` so reports can distinguish stable ELF x86-64 from
format-level and architecture-level preview gaps. Maturity-profile summaries
also count declared formats and architectures, making the current ELF x86-64
scope explicit instead of implying PE, Mach-O, ARM, or AArch64 parity. They
also count declared unit and end-to-end evidence paths so test coverage gaps are
visible at release-gate level.

The `maturity` section assigns every pass an explicit profile covering formats,
architectures, preconditions, invariants, affected instructions, false-positive
risk, unit and end-to-end tests, performance, decompiler effectiveness, and
pass-composition compatibility. Entries marked as not measured are deliberate
release gaps, not implied support.

The selection contract exposes only five short aliases through the CLI:
`nop`, `substitute`, `register`, `expand`, and `block`. The remaining entries
are engine-only capabilities until their configuration and end-to-end workflow
are promoted into the public CLI surface.

VM resistance artifacts currently cover 10 seeds with 255 handlers per seed,
0 exact normalized cross-seed handler matches, 12 handler stride values, and
target handler stride diversity. These are resistance indicators, not human
approval of anti-tamper or progressive bytecode protection. The generated
artifacts also carry `adversarial_validation.status` as
`pending-human-adversarial-review`, with seed diversity recorded as the current
evidence quality.
