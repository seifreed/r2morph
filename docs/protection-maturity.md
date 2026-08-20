# Protection Maturity Report

## 1. Current architecture

The production path audited here is `CodeVirtualizationPass` for ELF x86-64. It
has two generic lowering paths: straight-line register/FP runs and reducible or
dispatch-shaped control-flow regions. Generated VMs use per-build opcode maps,
duplicate handlers, direct-threaded encrypted dispatch, checksum-keyed operands,
scattered register frames, bounded frame-size variation, nested regions, and
fragmented executable payload loads.

The declared support contract is narrower than the repository's broader analysis
surface: ELF/x86-64 is the stable target; PE, Mach-O, and non-x86-64 rewriting
remain outside this pass.

## 2. Dataset coverage

`scripts/protection_maturity_baseline.py --all` discovers ELF64 `ET_EXEC` and
`ET_DYN` x86-64 files and excludes assembly sources and relocatable objects. The
current fixture inventory contains 109 compatible executable fixtures spanning
arithmetic, flags, calls, branches, switch tables, FP/SIMD, memory addressing,
PIE, red-zone, multi-exit, fallback, and nested-region shapes.

The machine-readable artifact is
[`docs/protection-maturity-corpus.json`](protection-maturity-corpus.json). Each
sample records SHA-256, size, format, architecture, function/basic-block/CFG and
instruction counts, strings, imports, references, runtime artifacts, Unicorn
exit status, and per-seed transform output hashes, sizes, timings, VM instruction
counts, and bytecode sizes. IDA/Hex-Rays evidence is recorded separately in this
ledger because the MCP adversary is an external analysis service rather than a
runtime dependency of the harness. The expanded representative evidence is in
[`docs/protection-ida-tierb.json`](protection-ida-tierb.json).

## 3. Semantic correctness passed/failed/skipped

Correctness is measured on the real generated ELF files, not mocks. The baseline
runner executes each original and each transformed output with Unicorn until the
exit syscall and compares the observed exit code. Native host execution is also
attempted; these synthetic ELF files are not Darwin-executable, so that backend
is recorded as an explicit `OSError` artifact rather than treated as a semantic
failure.

The completed campaign passed `109/109` fixtures and `1090/1090` seed runs. The
targeted current-checksum and adversary regressions pass, including real calls,
FP, switch, red-zone, and multi-exit fixtures. No fixture is silently skipped by
the virtualization pass; three explicit interpreter fixtures had zero
virtualized functions for every seed and are retained as no-op coverage results.

## 4. Obfuscation maturity technique-by-technique

| Technique | Evidence | Assessment |
|---|---|---|
| Opcode and operand polymorphism | Per-seed output hashes and bytecode sizes in corpus JSON | Effective diversity; not cryptographic secrecy |
| Handler duplication and body variation | Generated handler counts, shuffled emission, ISA/junk seeds | Raises static clustering cost |
| Direct-threaded dispatch | IDA ends representative entries at opaque `jmp rax` | Stronger than a plain switch; dynamic recovery remains possible |
| Checksum-keyed state | Hex-Rays recovers the checksum but not its downstream keys | Integrity and key dependency are visible |
| Register-frame scattering | Seed-derived slot permutation and spill order | Removes fixed frame fingerprints; frame semantics remain inferable |
| Handler clustering | [`docs/protection-handler-clustering.json`](protection-handler-clustering.json): normalized nearest similarity mean `0.846`, `1,903` of `2,232` comparisons >= `0.8` | Per-instance body variants reduce similarity slightly, but generic clustering remains effective |
| Bytecode grammar | [`docs/protection-bytecode-grammar.json`](protection-bytecode-grammar.json): target `mov`-64 handler strides change from fixed `[3]` to `[3,4,5]`; `2,566` padding bytes across `2,480` handlers | Removes one fixed cross-build record-stride assumption; opcode location and semantic field families remain visible |
| Anti-debug constants | Checksum-keyed constant island | No plaintext constants in representative entrypoints; runtime tracing still sees behavior |
| Fragmented RX payload | IDA segment surveys show adjacent RX loads | Adds layout work but remains fingerprintable |
| Control-flow virtualization | 109-fixture corpus and real exit-code checks | Broad synthetic semantic coverage; production format coverage is narrow |

## 5. Virtualization maturity

The pass virtualized 106 of 109 fixtures in the one-seed coverage run and records
the exact per-build result rather than claiming that every input is transformable.
The supported VM handles straight-line operations, branches, calls, flags,
memory forms, FP/SIMD forms, red-zone preservation, switch dispatch, multi-ret
regions, nested regions, and fallback paths represented by the fixture corpus.

The main maturity limit is not the happy path; it is the unsupported-input policy.
The pass conservatively leaves a function unchanged when it cannot prove the
required invariants. That is correct behavior, but it is not coverage parity with
a mature commercial protector across arbitrary PE, Mach-O, and non-x86 samples.

## 6. IDA/Hex-Rays

IDA Pro with Hex-Rays was used through the installed IDA MCP on fresh seed
`20260820` builds covering arithmetic, flag-live arithmetic, memory, RIP-relative
FP, indexed/packed FP, calls, absolute and PIE switches, red-zone, multi-exit,
and an interpreter outlier. Surveys consistently showed multiple adjacent RX
loads and a generated VM entry as a leaf function. Protected representative entry
sizes were 261 to 411 bytes; the interpreter outlier remained a five-function,
three-segment ordinary handler-table binary.

Hex-Rays recovered the checksum loop, its range, block size, rotate/mix operation,
and the final partial-block permutation. It did not recover a handler table or
bytecode semantics before the checksum-decrypted indirect transfer; the protected
entries ended in `jmp rax`. The interpreter outlier decompiled directly to
`handler_table[bytecode]()` and is therefore evidence of an unsupported/no-op
path, not protection resistance. This is a measured static result, not proof that
the complete VM resists a determined analyst.

The fresh seed `20260820` grammar build gave IDA three functions and seven
segments. Hex-Rays still decompiled the checksum bootstrap and the encrypted
relative-table load but recovered no handler functions, handler table, or bytecode
record grammar. The entry used a `0x2f0` frame and remained a 269-byte leaf ending
in `jmp rax`; the detailed observation is in
[`docs/protection-ida-bytecode-grammar.json`](protection-ida-bytecode-grammar.json).

## 7. Devirtualization

[`scripts/protection_adversary.py`](../scripts/protection_adversary.py) runs the
repository's own `VMHandlerAnalyzer` against the largest analyzed functions and
classifies outcomes as recovered table, unsupported indirect dispatch, or no VM
candidate. [`docs/protection-adversary.json`](protection-adversary.json) records
the current result: the analyzer did not recover handlers or bytecode from the
encrypted threaded build.

This failure is classified as unsupported current architecture, not as proof of
genuine devirtualization impossibility. The analyzer's positive generic oracle
remains covered by its existing real-fixture tests; the current encrypted table
and indirect dispatch are outside that analyzer's supported contract.

## 8. Multi-seed

The baseline command defaults to ten deterministic seeds `20260820` through
`20260829`. It records output hashes, sizes, transform duration, post-transform
static metrics, runtime artifacts, Unicorn exit code, virtualized instruction
count, bytecode bytes, and the per-instance record-padding grammar for every
seed/sample pair. Distinct sizes and hashes are expected; semantic equality is the
gate. The final counts are available in the corpus JSON summary and are not
inferred from one representative fixture. The engine's bytecode now assigns each
opcode instance zero, one, or two encrypted tail bytes; the handler emits the
matching stride.

## 9. Container fingerprintability

The payload container is still easy to identify structurally: appended adjacent
RX `PT_LOAD` ranges, a read-only metadata load, a large interpreter region, and
an entry that spills many registers before the checksum. Fragmentation changes
the shape and prevents a single-size signature, but it does not make the layout
blend into an ordinary ELF. This remains a material weakness.

## 10. Runtime analysis exposure

The bounded Unicorn trace in
[`docs/protection-runtime-trace.json`](protection-runtime-trace.json) observed a
fresh checksum build in `0.083` seconds: `54,048` instructions, `25` indirect
dispatches reaching `21` distinct targets, `256` register-state samples, and
`16,027` reads from executable ranges. Read values are hashed and samples are
capped. This demonstrates that a tracer can recover the handler sequence and
register state from the live process; the checksum is not an anti-tracing
boundary. The current harness records dispatch targets and read evidence, but
does not claim that a generic tracer cannot recover more, including the full
decoded bytecode stream.

## 11. Performance overhead

The corpus artifact records transform duration, Unicorn runtime duration, and
static-analysis duration for baseline and generated files. Across 1090 runs the
transform duration ranged from `0.037` to `0.909` seconds, averaging `0.458`
seconds. The checksum variant adds guarded tail handling and a four-byte block
loop, so it increases bootstrap work and entry size. Native runtime overhead is
unavailable on this host because the fixtures are synthetic ELF images rejected
by the Darwin loader.

## 12. Binary-size overhead

Each seed record contains original and output sizes, bytecode bytes, and output
hashes. Across the completed campaign, output-size ratios ranged from `1.0x` to
`63.59x`; generated bytecode ranged from `0` to `54,041` bytes. The entrypoint
hardening increases bootstrap bytes; handler multiplicity, duplicated threaded
decoders, frame variation, anti-debug island, and fragmented loads increase total
image size. The size increase is an intentional tradeoff, not a claim of low
overhead.

## 13. Weaknesses discovered

The adversary still sees a recognizable checksum bootstrap, a large register
spill, an obvious appended executable chain, and handler bodies that cluster at
`0.846` mean normalized nearest similarity across seeds. The opcode remains at
record offset zero, although per-instance tail padding now removes the fixed
record-stride assumption. The runtime VM's
dispatch sequence and register state were also recovered by the bounded trace.
The own devirtualizer does not support the current encrypted indirect shape, so
its negative result is not a complete adversarial benchmark. The interpreter outlier
shows that a direct handler-table architecture remains easy for Hex-Rays. Coverage
outside ELF x86-64 is not established. The strict repository quality gate also remains
blocked by the pre-existing forbidden Ruff `per-file-ignores` configuration and
the large lint backlog exposed when it is removed.

## 14. Fixed

The structural resistance probe now aggregates every executable segment within a
global budget instead of measuring only the largest fragment. Symbolic analysis
imports are lazy, avoiding optional-dependency warnings. VM register save order
and frame allocation vary deterministically per build. The checksum traversal now
uses seeded four-byte block permutations with guarded tails. Each change has real
regression coverage and was rechecked on fresh protected files. The runtime trace
harness and its bounded real-fixture regression make dynamic exposure measurable
without changing production protection behavior. Engine GP handlers now also use
two semantically equivalent field-decode/order forms selected per instance; the
handler-clustering artifact records the small but reproducible effect. Engine
bytecode records now add zero-to-two checksum-encrypted tail bytes per opcode
instance, with the generated handler stride and encoder stream kept in lockstep;
the grammar artifact and fresh IDA observation record the result.

## 15. Remaining gaps

The next material redesigns are a less fingerprintable payload container,
stronger semantic handler diversification, and broader format and architecture
support. Runtime tracing is now measured, but resisting it would require an
architectural change rather than more bootstrap opacity. Improving the current
devirtualizer to understand the encrypted
threaded contract is a separate tool-capability effort. None should be
implemented as a branch for a named sample or family. The quality-gate backlog
must be resolved as a separate repository-wide cleanup without adding lint
suppression.

## 16. Comparison with commercial properties

Compared with mature commercial protectors, this implementation has meaningful
per-build polymorphism, encrypted threaded dispatch, integrity coupling, and
real semantic validation on a broad synthetic x86-64 corpus. It remains behind
on format/architecture breadth, payload camouflage, runtime-tracing resistance,
devirtualizer maturity, operational hardening, and independently reproduced
large-corpus coverage. The comparison is directional and does not assign vendor
claims to measurements unavailable in this repository.

## 17. Final scores

Scores are deliberately conservative on a 0–5 scale:

| Dimension | Score | Basis |
|---|---:|---|
| Supported-corpus semantic correctness | 5.0 | Real Unicorn exit-code parity across the measured corpus |
| Seed diversity | 4.0 | Ten deterministic builds with per-build hashes/sizes and unchanged semantics |
| Static resistance | 3.0 | Opaque dispatch and unrecovered handlers, visible checksum/container |
| Own devirtualizer resistance | 2.0 | Negative result is partly unsupported-adversary capability |
| Runtime-analysis resistance | 1.0 | VM behavior remains observable under tracing |
| Format and architecture coverage | 1.5 | Production virtualization path is ELF x86-64 |
| Commercial parity | 1.5 | Useful primitives, substantial maturity gaps remain |

## 18. Commits

The previously pushed maturity loop includes `d63efec`, `f3143ea`, `4cf6106`,
`6724082`, `1b0b761`, and `ed409e8`. Commit `c701ef3` adds the corpus baseline,
own-adversary harness, real regression coverage, and checksum block permutation.
Commit `08f637a` adds bounded runtime dispatch tracing and its real-fixture
regression. Commit `c161b22` expands the IDA/Hex-Rays Tier B evidence with
memory, flag-live, FP, PIE, and interpreter cases. It must not be described as
fully green until the repository quality
gate passes without the forbidden Ruff per-file exclusions; that blocker is
recorded explicitly rather than hidden. Commit `fc9e1cc` measures cross-seed
handler clustering, adds semantically equivalent GP handler variants, and
regenerates the multi-seed corpus.
