# Protection Maturity Report

Commit: `b8e5638`
Date: `2026-08-20`

## 1. Current architecture

The production path audited here is `CodeVirtualizationPass` for ELF x86-64. It
has two generic lowering paths: straight-line register/FP runs and reducible or
dispatch-shaped control-flow regions. Generated VMs use per-build opcode maps,
duplicate handlers, direct-threaded encrypted dispatch, checksum-keyed operands,
scattered register frames, per-build state-mask slots, bounded frame-size variation, nested regions, and
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
| Checksum-keyed state | Hex-Rays recovers either a four-byte permutation or bytewise checksum, but not downstream keys | Integrity and key dependency are visible; traversal shape varies per build |
| Register-frame scattering | Seed-derived slot permutation and spill order | Removes fixed frame fingerprints; frame semantics remain inferable |
| Handler clustering | [`docs/protection-handler-clustering.json`](protection-handler-clustering.json): normalized nearest similarity mean `0.838`, `1,780` of `2,232` comparisons >= `0.8` | Per-instance body variants reduce similarity slightly, but generic clustering remains effective |
| Bytecode grammar | [`docs/protection-bytecode-grammar.json`](protection-bytecode-grammar.json): target `mov`-64 handler strides change from fixed `[3]` to `[3,4,5]`; `2,566` padding bytes across `2,480` handlers. Immediate `add`/`and`/`or`/`sub`/`xor` also select one- or two-fold decompositions per build | Removes fixed record stride and adds generic arithmetic decomposition; opcode location and semantic field families remain visible |
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

The fresh seed `20260820` grammar build gave IDA three functions and five
segments. Hex-Rays still decompiled the checksum bootstrap and the encrypted
relative-table load but recovered no handler functions, handler table, or bytecode
record grammar. The entry used a `0x2f0` frame and remained a 269-byte leaf ending
in `jmp rax`; the detailed observation is in
[`docs/protection-ida-bytecode-grammar.json`](protection-ida-bytecode-grammar.json).

The current immediate-decomposition build gave IDA three functions and six
segments. Its 276-byte VM entry still decompiled to the checksum loop, guarded
tail handling, and `jmp rax`; no handler functions, table, or bytecode grammar
were recovered. The dedicated observation is in
[`docs/protection-ida-immediate-decomposition.json`](protection-ida-immediate-decomposition.json).

Commit `f5f0b35` keeps the engine VM's vPC, bytecode base, and position encoded
with the runtime checksum key at each indirect dispatch. The handler decodes the
three registers only after control arrives, so existing handler bodies and the
semantic contract remain unchanged. The controlled before/after evidence is in
[`docs/protection-state-encoding.json`](protection-state-encoding.json).
Commit `e32ad9c` extends the state protocol to region and nested handlers, with
real regressions and same-fixture trace comparisons for both paths.

Commit `e32ad9c` extends the same protocol through region and nested handler
entries. The controlled region comparison removed `22/22` raw position matches;
the nested in-call comparison removed `244/244` while preserving exit `45`.
IDA on the current region build recognized two functions and four segments; its
177-byte VM entry decompiled only to the checksum loop and opaque `jmp rax`, with
no handler recovery. This matches the engine result: state encoding changes the
runtime correlation without claiming that the checksum bootstrap itself is hidden.

Commit `e078722` separates the live-state mask from the operand key. The engine
frame now reserves a randomized state slot; region and nested VMs use the fixed
state slot `0x218`. Bootstrap derives the mask from the caller's runtime stack
address, rotates it, and mixes the checksum, while bytecode operand encoding stays
unchanged. On the same engine fixture and seed, the protected file grew from
`82183` to `82211` bytes and from `212586` to `212681` traced instructions, kept
exit `42`, kept `38` indirect jumps, and retained `0/35` raw-position matches.
The current environment had no IDA executable available for a fresh post-change
decompilation, so no new Hex-Rays claim is made here; the existing same-shape IDA
survey remains the static reference.

Commit `b8e5638` separates bootstrap integrity from the full dispatch integrity
contract. The entry computes a short key over `[vm_entry, vm_bootstrap)` for the
bootstrap table and probes; the `ready` path then recomputes the full key over
`[vm_entry, vm_table)` before initializing operand keys, state, and threaded
dispatch. On the same fixture and seed, the protected file is `82344` bytes with
`213899` traced instructions, `38` indirect jumps, exit `42`, and `0/35` raw
position matches. Fresh IDA survey reports three functions and seven RX segments.
Hex-Rays still decompiles the entry to the first checksum loop and `jmp rax`, but
IDA disassembly separately exposes the second checksum loop at `0x404193` before
key/state setup; no handler table or bytecode grammar was recovered. The exact
artifact is recorded in [`docs/protection-state-encoding.json`](protection-state-encoding.json).

The region and nested VMs now choose the runtime state-mask slot from the free
qword window of each generated frame and share the outer slot across nested
layers. On `elf_vm_arith_x86_64`, seed `20260820`, the protected file exits `45`,
has `22` correlated dispatches and `0` raw position matches, and IDA shows the
state at `[rsp+220h]` rather than the previous fixed `[rsp+218h]`. Hex-Rays still
recovers only the checksum loop and opaque `jmp rax`; no handler table or
bytecode grammar was recovered. The fresh artifact is recorded in
[`docs/protection-state-encoding.json`](protection-state-encoding.json).

Commit `9d1a334` adds a second checksum traversal selected from existing per-build
scheme fields without shifting later randomness. On seed `20260822`, IDA saw a
183-byte, three-block entry and Hex-Rays reduced the bootstrap to a bytewise
`i += 1` loop with `v0 = ROL1(v0 - byte, 5)`. No handlers or bytecode grammar were
recovered. The prior block-mode sample recovered an 11-block, 269-byte entry with
four-byte permutation and guarded tail reads. The focused comparison is in
[`docs/protection-ida-checksum-bytewise.json`](protection-ida-checksum-bytewise.json).

## 7. Devirtualization

[`scripts/protection_adversary.py`](../scripts/protection_adversary.py) runs the
repository's own `VMHandlerAnalyzer` against the largest analyzed functions and
classifies outcomes as recovered table, unsupported indirect dispatch, or no VM
candidate. [`docs/protection-adversary.json`](protection-adversary.json) records
the prior checksum-seed result; the current same-fixture state-encoding result is
in [`docs/protection-state-encoding.json`](protection-state-encoding.json). In
both cases the analyzer did not recover handlers or bytecode from the encrypted
threaded build.

This failure is classified as unsupported current architecture, not as proof of
genuine devirtualization impossibility. The analyzer's positive generic oracle
remains covered by its existing real-fixture tests; the current encrypted table
and indirect dispatch are outside that analyzer's supported contract. The
adversary also exposed and fixed a false table candidate from non-executable ELF
header bytes; current recovery now rejects that candidate on segment metadata.
The separate bounded dynamic harness now supplies the missing capability
distinction. Before `f5f0b35`, the same fixture/seed exposed `35/35` tuples where
`vpc - bytecode_base == position`; after the change it exposed `0/35`, while the
program still exited `42`. The own adversary reports this as encoded state rather
than incorrectly claiming raw recovery; it still sees `12` handler targets and
the target sequence, so this is a state-exposure reduction, not full dynamic
resistance. It does not retain decoded payload bytes.

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
For the dedicated `elf_vm_engarithimm_x86_64` fixture, four of ten seeds changed
bytecode size by `24` to `27` bytes; across the corpus, `45/1090` runs changed in
eight fixtures. All `1090/1090` semantic checks passed. The decomposition is
selected per build and applies only to generic associative arithmetic immediate
micro-ops. The checksum traversal update changes `948/1090` outputs across `106`
fixtures and changes aggregate output size by `-56,498` bytes; all semantic checks
remain green. It selects bytewise or block traversal without consuming additional
randomness, so unrelated handler and junk decisions remain stable.

## 9. Container fingerprintability

The payload container is still easy to identify structurally: appended adjacent
RX `PT_LOAD` ranges, a large interpreter region, and an entry that spills many
registers before the checksum. The injector now maps the relocated program-header
table inside the first appended RX load, removing the standalone metadata load;
the representative ELF load count falls from `7` to `6`. Fragmentation changes
the shape and prevents a single-size signature, but it does not make the layout
blend into an ordinary ELF. This remains a material weakness.

## 10. Runtime analysis exposure

The historical bounded Unicorn trace in
[`docs/protection-runtime-trace.json`](protection-runtime-trace.json) observed a
fresh bytewise checksum build in `0.335` seconds: `253,680` instructions, `35`
indirect dispatches reaching `14` distinct targets, `256` register-state samples,
and `50,343` reads from executable ranges. Read values are hashed and samples are
capped. Of those jumps, `32` are correlated with a non-zero bytecode base, vIP,
stream position, and handler target; the artifact keeps an eight-event bounded
sample. This demonstrates that a tracer can recover the handler sequence and
register state from the live process; the checksum is not an anti-tracing
boundary. The harness now records the correlation explicitly, but does not claim
that a generic tracer cannot recover more, including the full decoded bytecode
stream.

The controlled comparison in
[`docs/protection-state-encoding.json`](protection-state-encoding.json) measured
`35/35` raw position matches before and `0/35` after. The output grew from
`70,255` to `82,183` bytes (`+17.0%`) and the bounded run from `173,610` to
`212,586` instructions (`+22.5%`); both builds exited `42`. This protects only
the engine, region, and nested paths in the measured contracts; raw target
sequences remain observable.

## 11. Performance overhead

The corpus artifact records transform duration, Unicorn runtime duration, and
static-analysis duration for baseline and generated files. Across 1090 runs the
transform duration ranged from `0.037` to `0.909` seconds, averaging `0.458`
seconds. The checksum variants add either a guarded four-byte permutation loop or
a bytewise loop; the latter is shorter in the representative IDA sample. Native
runtime overhead is
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
`0.838` mean normalized nearest similarity across seeds (`1780` pairings remain
at or above `0.8`). The equivalent per-instance vIP advance form reduces this
signal without adding unreachable junk. The opcode remains at record offset
zero, although per-instance tail padding now removes the fixed record-stride
assumption. The engine VM's raw vPC/base/position correlation was recovered at
`35/35` dispatches before `f5f0b35` and at `0/35` after it. The region and nested
comparisons in the state-encoding artifact show the same `0` raw matches. The
target sequence and handler count remain visible, so handler semantics and
bytecode records are not claimed to be hidden by this change.
Immediate arithmetic now has a second generic lowering grammar for `add`, `and`,
`or`, `sub`, and `xor`; the current IDA observation still recovered no handler
grammar. The checksum now has two generic traversal grammars: the block mode is
still visibly structured and the bytewise mode is simpler but no longer identical
across builds.
The two-stage integrity change removes the single full-span bootstrap contract,
but both checksum loops remain statically recoverable and the handler-target
sequence remains observable.
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
uses either seeded four-byte block permutations with guarded tails or a bytewise
walk. Each change has real
regression coverage and was rechecked on fresh protected files. The runtime trace
harness and its bounded real-fixture regression make dynamic exposure measurable
without changing production protection behavior. Commit `a6ac9ed` adds the
dispatch-context correlation to that harness. Commit `c0cc5f0` exposes the same
bounded recovery in the own adversary. Engine GP handlers now also use
two semantically equivalent field-decode/order forms selected per instance; the
handler-clustering artifact records the small but reproducible effect. Engine
bytecode records now add zero-to-two checksum-encrypted tail bytes per opcode
instance, with the generated handler stride and encoder stream kept in lockstep;
the grammar artifact and fresh IDA observation record the result. The relocated
program-header table now shares the first appended RX load, removing one
synthetic metadata segment while preserving the loader invariants.
Handler tails also select the equivalent `add` or flag-neutral `lea` vIP advance
form per instance; the clustering artifact records the reduction in nearest
similarity.
Immediate `add`, `and`, `or`, `sub`, and `xor` can now lower as two sequential
equivalent folds selected per build; the dedicated corpus and IDA artifact record
the semantic and static results. Commit `9d1a334` adds the seed-derived bytewise
checksum traversal, its unit regression, full-corpus evidence, bounded trace, and
fresh Hex-Rays observation. Commit `f5f0b35` encodes the engine VM's live vPC,
bytecode base, and position between handlers; the new unit/integration regression,
same-fixture trace comparison, and IDA recheck are recorded in
[`docs/protection-state-encoding.json`](protection-state-encoding.json).
Commit `e32ad9c` extends the encoded state protocol to region and nested VMs,
with real regressions and same-fixture trace comparisons for both paths.
Commit `b8e5638` defers the full integrity key until bootstrap readiness and
records the fresh two-loop IDA observation in the state-encoding artifact.
The state-slot change is covered by `33` focused tests, `137` real integration
tests, and `1090/1090` Tier A seed runs; its code commit and final gate result
are recorded below.

## 15. Remaining gaps

The current layout, handler-tail, engine-state, and region-state changes reduce measured
signals, but the
payload is still an appended RX chain and the abstract machine remains
recognizable across builds. Further container camouflage would require a new
multi-region placement contract, not another segment or padding tweak. Stronger
semantic diversity would require alternate state encodings or instruction
decomposition across both virtualization paths, with a substantially broader
semantic oracle. Runtime tracing remains observable and resisting it requires an
execution-architecture change. Improving the current devirtualizer to understand
the encrypted threaded contract is a separate tool-capability effort. Broader
format/architecture support is outside the declared virtualization envelope.
None should be implemented as a branch for a named sample or family. The
quality-gate backlog must be resolved as a separate repository-wide cleanup
without adding lint suppression.

### Termination assessment

At HEAD `b8e5638`, the remaining protection weaknesses require architectural
changes rather than another local polymorphism axis. The two-stage integrity
contract removes one single full-span loop, but both the short bootstrap loop and
the deferred full loop remain statically recoverable. Removing that fingerprint
requires distributing integrity state across the VM entry and threaded handlers
while preserving the encoder/checksum contract. The appended RX chain remains an
ELF-container fingerprint; hiding it requires a new placement contract that can
use multiple existing executable regions and preserve loader invariants. Runtime
traces still recover handler targets, and the raw target sequence remains
observable; reducing that exposure requires a different execution model, not more
static junk or another checksum spelling. The loop remains active because
`b8e5638` produced a measured key-lifecycle change; checksum-loop recovery,
container fingerprinting, and target-sequence exposure remain open weaknesses.

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
regenerates the multi-seed corpus. Commit `8895156` adds per-opcode encrypted
bytecode tail padding, its stride/grammar measurement, fresh Tier B IDA evidence,
and the regenerated correctness corpus. Commit `dba52f7` maps the relocated
program-header table inside the first appended RX load, removes the standalone
metadata load, and revalidates the full corpus and loader invariants. Commit
`99fe143` adds equivalent per-instance `add`/`lea` vIP advances, updates the
clustering and Tier B artifacts, and revalidates the full suite. The follow-up
evidence commit records the regenerated 109-fixture corpus hashes and timing
metrics from that build. Commit `8e8b3f9` is the handler-diversity evidence
snapshot. Commit `cfc6c2d` fixes false VM handler-table recovery from
non-executable bytes, adds its real-fixture regression, and refreshes the
adversary artifact. Commit `b75ce62` adds per-build immediate arithmetic
decomposition for `add`, `sub`, and `xor`, its regression, the regenerated
corpus, and current IDA/adversary evidence. Commit `b6159be` extends that
decomposition to `and` and `or`, with its regression, regenerated corpus, and
current IDA/adversary evidence. Commit `9d1a334` adds the generic bytewise checksum
traversal and its real regression/corpus/IDA evidence. The remaining gaps above are
architectural rather than unmeasured local variations. Commit `c0cc5f0` integrates
the correlated runtime recovery into the own adversary without changing the
protected binary. The official quality wrapper was rerun at this
HEAD: 9 checks pass;
the only failure is the pre-existing forbidden Ruff `per-file-ignores` block,
whose removal exposes 11,893 unsuppressed findings (9,607 are test assertions).
Commit `f5f0b35` encodes engine VM state across threaded dispatch, adds the
raw-position adversary contract, and records same-fixture semantic, runtime,
performance, and IDA evidence in `protection-state-encoding.json`. The gate was
rerun after this commit: 9 checks pass and the same single configuration failure
remains. Commit `e32ad9c` extends the encoded state protocol to region and nested
VMs; the gate was rerun again with the same `9` passes and only the forbidden
`per-file-ignores` failure.
Commit `e078722` separates the runtime state mask from the operand key across
engine, region, and nested VMs; the focused protection suite passed `174` tests.
The full gate remains blocked by environment/tooling warnings and existing
configuration/dependency findings documented in the session ledger.
Commit `b8e5638` splits bootstrap and full integrity keys across engine, region,
and nested VMs; the focused protection suite passed `170` tests after the final
helper refactor, and the fresh same-fixture IDA/runtime evidence is recorded above.
