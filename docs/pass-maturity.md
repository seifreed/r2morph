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

The continuous composition smoke exercises six directional pairs among
`NopInsertion`, `InstructionSubstitution`, and `ConstantUnfolding`, both orders
of `NopInsertion` with each of the twelve extended maturity passes, and fourteen
applied core-pass compositions on dedicated fixtures. The workflow requires
all 44 directional pairs and all 46 real-fixture test cases. `StackStrings`
now has a native regression for its supported ELF x86-64 direct-call and optimized tail-jump rewrites;
references without a safe shape, unsupported encodings, and unavailable caves
remain explicit no-op cases.
The pass-ordering and runtime-preservation checks live in
`tests/integration/test_polymorphic_engine_real.py`. This closes the declared
two-pass order matrix; arbitrary pass-order combinations remain outside the
contract until they have equivalent real-fixture coverage.

| Pass | Status | Target | Current limitation | Evidence |
|---|---|---|---|---|
| NOP insertion | Tier 1 | Linux ELF x86-64; PE x86-64 and Mach-O x86-64/AArch64 preview | Preview targets require real structural validation and checksum/signature handling; no official cross-platform contract | `tests/product_smoke`, `tests/integration`, `tests/integration/test_nop_insertion_pe_real.py`, `tests/integration/test_mutation_nop_insertion_arm64.py`, `tests/integration/test_mutations_x86_compiled_binary.py` |
| Instruction substitution | Tier 1 | Linux ELF x86-64; PE x86-64 and Mach-O AArch64 preview | Rule coverage is ISA-specific; preview evidence covers one real PE fixture and direct 12-bit ARM64 move-immediate substitutions | `tests/product_smoke`, `tests/integration`, `tests/integration/test_mutation_nop_insertion_arm64.py`, `tests/integration/test_mutation_passes_end_to_end_more2.py` |
| Register substitution | Tier 1 | Linux ELF x86-64; PE x86-64 and Mach-O AArch64 preview | Requires proven liveness and ABI preservation; non-ELF targets remain experimental | `tests/product_smoke`, `tests/integration`, `tests/integration/test_nop_insertion_pe_real.py`, `tests/integration/test_mutation_register_substitution_arm64.py` |
| Instruction expansion | Experimental | ELF x86-64 | Selected by the compatibility corpus and current composition smoke; wider replacements still need cross-platform evidence and analyzer-effectiveness results | `README.md`, `docs/compatibility-corpus.md` |
| Block reordering | Experimental | ELF x86-64 | Selected by the compatibility corpus and current composition smoke; complex indirect control flow is rejected | `tests/integration`, `docs/compatibility-corpus.md` |
| Dead code injection | Experimental | ELF x86-64 | Selected by the compatibility corpus and current composition smoke; placement depends on available safe regions and analyzer-effectiveness evidence remains incomplete | `tests/integration/test_dead_code_injection_flag_safe_real.py`, `tests/integration/test_protection_maturity_baseline.py`, `docs/compatibility-corpus.md` |
| Control-flow flattening | Experimental | ELF x86-64 | Selected by the compatibility corpus and current composition smoke; cross-tool decompiler evidence remains incomplete | `tests/integration/test_control_flow_flattening_flag_safe_real.py`, `tests/integration/test_protection_maturity_baseline.py`, `docs/compatibility-corpus.md` |
| Opaque predicates | Experimental | ELF x86-64 | Predicate families are not exhaustive | `README.md` |
| Code virtualization | Experimental | ELF x86-64 | Selected by the compatibility corpus and current composition smoke; unsupported functions are rejected or conservatively unchanged with diagnostics | `docs/protection-maturity.md`, `docs/compatibility-corpus.md`, `tests/integration/test_code_virtualization_generic_isa_real.py` |
| Anti-disassembly | Experimental | ELF x86-64 | No independent review evidence | `README.md` |
| Data-flow mutation | Experimental | ELF x86-64 | Narrow instruction family | `README.md` |
| Short-jump patching | Experimental | ELF x86-64 | Needs more relocation coverage | `README.md` |
| Constant unfolding | Experimental | ELF x86-64 | Selected by the compatibility corpus; x86-only transformation rules and analyzer-effectiveness evidence remain incomplete | `tests/integration/test_protection_maturity_baseline.py`, `fixtures/dataset/elf_constant_unfold_x86_64.S`, `docs/compatibility-corpus.md` |
| Code mobility | Experimental | ELF x86-64 | Code-cave geometry is input-dependent | `README.md` |
| Function outlining | Experimental | ELF x86-64 | ABI and exception edges need more evidence | `README.md` |
| API hashing | Experimental | ELF x86-64 | External symbol behavior is environment-dependent | `README.md` |
| Import obfuscation | Experimental | ELF x86-64 | Format-specific import handling | `README.md` |
| Self-modifying code | Experimental | ELF x86-64 | Runtime validation is mandatory and limited | `README.md` |
| Stack strings | Experimental | ELF x86-64 | Rewrites unique RIP-relative direct-call arguments only; unsupported references, encodings, and targets remain no-op | `README.md`, `tests/integration/test_polymorphic_engine_real.py` |
| String obfuscation | Experimental | ELF x86-64 | Runtime string reconstruction is environment-dependent | `README.md` |
| Pattern substitution | Experimental | ELF x86-64 | Selected by the compatibility corpus and current composition smoke; pattern coverage is intentionally narrow | `README.md`, `docs/compatibility-corpus.md` |
| Polymorphic engine | Experimental | ELF x86-64 | The current real ELF x86-64 smoke covers 46 cases and 44 directional pairs; arbitrary combinations remain unsupported | `tests/integration/test_polymorphic_engine_real.py`, `README.md` |

The machine-readable format and evidence paths are in
[`support-matrix.json`](support-matrix.json). A pass cannot be promoted by a
single fixture or a static disassembly result alone.
The generated matrix summary records evidenced versus not-supported cells,
including official and non-official targets, so the Linux ELF x86-64 baseline
and PE, Mach-O, ARM, and AArch64 parity gaps are visible without expanding every
cell. It also records evidence percentages for official and non-official targets
so preview coverage cannot look equivalent to the supported baseline. The
current matrix records 100.0% official evidence, 6.61% non-official evidence,
16 non-official evidenced cells, and 226 non-official not-supported cells. It
also lists 11 non-official format/architecture targets in
`non_official_gap_targets`; Mach-O AArch64, Mach-O x86-64, PE x86-64, and ELF
ARM currently have preview evidence, while ELF AArch64/x86, Mach-O ARM/x86,
and PE AArch64/ARM/x86 remain at 0.0% evidence. The generated
`total_parity_blockers` count is currently 16 total parity blockers. It
also counts passes per declared
stability and maturity profile so Tier 1, corpus-selected,
anti-disassembly-instruction-catalogued,
api-hashing-instruction-catalogued,
code-mobility-instruction-catalogued,
code-virtualization, data-flow-mutation-instruction-catalogued,
import-obfuscation-instruction-catalogued,
opaque-predicates-instruction-catalogued,
polymorphic-engine-instruction-catalogued,
self-modifying-code-instruction-catalogued,
short-jump-patching-instruction-catalogued,
function-outlining-instruction-catalogued,
stack-strings-instruction-catalogued,
string-obfuscation-instruction-catalogued, and experimental coverage remain visible at release-gate
level: 3 tier-1 passes, 19 experimental passes, 3 tier-1-native profile passes,
6 experimental-corpus-selected profile passes, 1
anti-disassembly-instruction-catalogued profile pass, 1 api-hashing-instruction-catalogued
profile pass, 1 code-mobility-instruction-catalogued profile pass, 1 code-virtualization profile
pass, 1 data-flow-mutation-instruction-catalogued profile pass, 1
function-outlining-instruction-catalogued profile pass, 1
import-obfuscation-instruction-catalogued profile pass, 1
opaque-predicates-instruction-catalogued profile pass, 1
polymorphic-engine-instruction-catalogued profile pass, 1
self-modifying-code-instruction-catalogued profile pass, 1
short-jump-patching-instruction-catalogued profile pass, 1
stack-strings-instruction-catalogued profile pass, 1
string-obfuscation-instruction-catalogued profile pass. It also summarizes the declared
performance, false-positive-risk,
instructions-affected, decompiler-effectiveness, and compatibility/composition
text by profile so unmeasured cost, ISA coverage, risk, analyzer effectiveness,
and pass-composition gaps remain visible release gaps instead of being buried in
each pass row.
The scheduled extended maturity smoke now records output-size,
transform-duration, runtime-duration, and static metric summaries for every
selected pass. It now also executes generated argv inputs and records
`behavioral_validation_observations`,
`behavioral_false_positive_observations`, and
`behavioral_false_positive_rate_percent` for every applied run. A non-zero
rate or missing observation fails the scheduled evidence gate. The same gate
also compares every applicable applied run against the independent Unicorn
exit-code oracle and rejects missing or divergent oracle observations; this is the
native-runtime oracle for behavioral false positives, not a static-risk claim.
Applied mutation records now also contribute a bounded
`affected_instruction_mnemonics` catalogue and record count per pass. An
applied run without those records is a release-gate blocker, so an instruction
family cannot appear covered only because a binary changed on disk.
The aggregate job now persists these per-pass results as
`extended-maturity-merged.json` alongside the differential corpus artifact,
so the evidence is retained as a reviewable campaign output rather than only
being checked transiently inside a runner.
The same aggregate job now publishes `maturity-evidence-merged.json`. It joins
the differential and extended-pass summaries with the composition JUnit shards
and records, per pass, whether performance, behavioral validation, affected
instructions, composition, and analyzer evidence is complete, partial,
preview-only, or pending. This artifact is a reporting contract: a passing
workflow does not promote partial analyzer coverage or a preview-only pass to
official support.
The static profile summary remains a declared-gap view: it still reports 12
with no independent false-positive measurement, 12 with no independent
decompiler-effectiveness measurement, 11 without contractual composition
support, and 35 total per-pass maturity field gaps across 3 maturity gap
categories, with no remaining exhaustive affected-instruction catalogue gap in
the static profiles. The current
last archived scheduled artifact records ten passes without independent semantic
false-positive observations, eight without contractual composition support,
22 without comparable decompiler evidence, and one without an applied
affected-instruction catalogue: 41 per-pass evidence blockers across four
measured categories. Performance coverage is complete in that artifact. The
current tracked composition smoke adds applied evidence for the extended
composition cases, including the scoped `StackStrings` native rewrite; the next
scheduled aggregate must confirm that reduction before the archived totals are
replaced. The
generated matrix also names the affected passes in
`maturity_gap_passes`, so per-pass maturity gaps are reviewable without
reconstructing them from profile text. It also publishes the inverse
`maturity_gaps_by_pass` map so each pass's remaining maturity blockers are
visible directly. It also publishes `native_evidence_gap_passes`, listing every
pass that has not reached a native evidence profile.
The generated summary also exposes `parity_gap_scope`, naming Mach-O and PE as
format gaps and AArch64, ARM, and x86 as architecture gaps. Maturity-profile
summaries also count declared formats and architectures, making the current ELF
x86-64 scope explicit instead of implying PE, Mach-O, ARM, or AArch64 parity.
They also count declared unit and end-to-end evidence paths so test coverage
gaps are visible at release-gate level. The continuous differential workflow
also runs three ELF ARM32 cases under `qemu-arm`, three ELF AArch64 cases under
`qemu-aarch64`, and three native ELF x86 32-bit cases covering NOP insertion,
instruction substitution, and register substitution; they are preview evidence
only and do not close the per-pass ARM, AArch64, or x86 parity gaps.

The `maturity` section assigns every pass an explicit profile covering formats,
architectures, preconditions, invariants, affected instructions, false-positive
risk, unit and end-to-end tests, performance, decompiler effectiveness, and
pass-composition compatibility. Entries marked as not measured are deliberate
release gaps, not implied support.
The Tier 1 native profile now links a focused adversarial corpus summary for
NopInsertion, InstructionSubstitution, and RegisterSubstitution:
[`protection-adversarial-tier1-2026-09-13-400c2a48-summary.json`](protection-adversarial-tier1-2026-09-13-400c2a48-summary.json).
That run completed `angr`, radare2, objdump, and the custom analyzer across all
483 Tier 1 pass/sample rows, with Unicorn completing 463 rows. Binary Ninja
remains an explicit unavailable-tool blocker; IDA, Ghidra, and Triton have
separate corpus evidence, but the full comparable campaign scope remains a
release blocker.
The aggregate jobs of the current four-shard 22-pass campaign
[`35021131440`](https://github.com/seifreed/r2morph/actions/runs/35021131440)
completed 11,682 pass runs (5,310 core and 6,372 extended) with no
transformation, semantic, or runtime-observable errors. It provides continuous
output-size, duration, static-metric, and behavioral evidence for all 22 declared
passes. The separate public compatibility-corpus job in that run is still
pending completion. The merged maturity artifact
records zero performance-field gaps, ten passes without independent semantic
false-positive observations, eight without contractual composition coverage,
22 without comparable decompiler evidence, and `StackStrings` without an
applied instruction catalogue. The current follow-up smoke has applied
composition evidence for the extended passes, including `StackStrings`; these
remain release gaps until the scheduled aggregate publishes the updated
artifact.
The generated summary also exposes `vm_semantic_gap_scope` so memory,
direct/indirect calls, ABI/varargs, unwinding/exceptions, TLS/signals, threads,
FP/SIMD, and SSA/liveness remain machine-readable VM blockers. SSA/liveness
preflight coverage is backed by the static dataflow, def-use, and liveness
regression contracts, including the installed-wheel smoke in the scheduled
differential campaign. The companion `total_vm_semantic_blockers` count is currently 9 VM semantic
blockers.

The VM semantic fixture inventory is exercised by the bounded native parity
campaign in [`scripts/vm_semantic_campaign.py`](../scripts/vm_semantic_campaign.py).
Every scheduled run processes all 151 ELF x86-64 fixtures from
[`virtualization-coverage.json`](virtualization-coverage.json), preserves the
executable mode in a temporary copy, requires one applied virtualization, and
compares return code, termination signal, hashed stdout/stderr, and bounded
created-file hashes, sizes, and modes before and after the mutation. The
workflow repeats that complete fixture set across three
deterministic seeds, for 453 fixture runs, retains the JSON result as an
artifact, and fails on any missing, non-virtualized, or divergent fixture. The
latest passing campaign is retained in
[`protection-vm-semantic-2026-09-18-1d0b69e4.json`](protection-vm-semantic-2026-09-18-1d0b69e4.json).
The artifact also reports each declared capability explicitly: memory, calls,
ABI/varargs, ordinary unwind metadata, non-linear CFG SSA/liveness,
TLS/signals, threads, and FP/SIMD are campaign-measured. LSDA/landing-pad
exception transformation remains fail-closed and is separately covered by
real regression contracts; the campaign does not claim full language-level
exception virtualization. Fixture runs still do not prove arbitrary inputs,
unsupported ABIs, or cross-platform parity.
The archived local run
[`protection-vm-semantic-2026-09-16-7356a474.json`](protection-vm-semantic-2026-09-16-7356a474.json)
completed 150 fixtures with zero failures for the official Linux ELF x86-64
target; the current scheduled inventory is the 151-fixture campaign described
above.

The companion adversarial aggregate
[`34999775170`](https://github.com/seifreed/r2morph/actions/runs/34999775170)
completed its four shards and aggregate validation without pass or analyzer
errors. Binary Ninja, IDA Pro, and Ghidra remained unavailable, and 132 Unicorn
rows lacked the required ISA capability; those rows remain explicit analyzer
coverage blockers.

The selection contract exposes only five short aliases through the CLI:
`nop`, `substitute`, `register`, `expand`, and `block`. The remaining entries
are engine-only capabilities until their configuration and end-to-end workflow
are promoted into the public CLI surface.

VM resistance artifacts currently cover 10 seeds with 255 handlers per seed
across five tracked ELF x86-64 fixtures,
0 exact normalized cross-seed handler matches, 12 handler stride values, and
target handler stride diversity. These are resistance indicators, not human
approval of anti-tamper or progressive bytecode protection. The generated
artifacts also carry `adversarial_validation.status` as
`pending-human-adversarial-review`, with seed diversity recorded as the current
evidence quality. The scheduled adversarial workflow additionally runs six real
tamper/progressive protection tests and publishes JUnit evidence, including
single-level tamper, nested tamper, nested growth, and diversified-build
checks. This strengthens automated evidence but does not replace the pending
human/adversarial review. The generated `total_vm_resistance_blockers` count is
currently 6 VM resistance blockers.
The local refresh
[`protection-vm-resistance-2026-09-19-3feec419.json`](protection-vm-resistance-2026-09-19-3feec419.json)
extends that evidence across five tracked ELF x86-64 fixtures: semantic parity,
cross-fixture artifact diversity, single- and nested-layer tamper divergence,
and progressive bytecode growth all passed across ten seeds. Its human review
field remains pending by contract.
The same workflow now publishes `vm-resistance-adversarial.json`, a bounded
ten-seed report that joins semantic parity, distinct artifact hashes,
opcode-assignment, dispatcher/handler/stride diversity, single- and nested-layer tamper
divergence, and progressive blob growth. Its `human_adversarial_review` field
remains pending by contract, so the report is continuous automated evidence
rather than a human signoff.
