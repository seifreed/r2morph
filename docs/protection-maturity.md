# Protection Maturity Report

Commit: `45cb3ee`
Date: `2026-08-28`

## Current verification status

The supported Python 3.12 environment passed the required static and security
gates. GitHub Actions run `33057629050` completed successfully with all 16 jobs
on commit `0f4ea3f`, including the Linux/Python 3.12 suite and cross-platform
matrix. The complete local gate was also run; binary tests were sensitive to
concurrent host load, so the clean CI suite is the authoritative result.

The public compatibility corpus is pinned to commit
`8267a9234a61939c7c3ef5514983fbd9285d41a0`. The preceding green Linux campaign
at `2692223051130087bdae9f7b148d380856de91cf` passed `160/160` built samples
and its static-recovery benchmark measured `160/160` passed samples. A local
macOS reproduction built `80/160` samples,
with the remaining records explicitly omitted because static linking was not
available; all `80/80` built samples passed transformation and differential
execution and static recovery. Decompiler effectiveness remains explicitly
unmeasured where no licensed or public runner is available. The current corpus
run for the pinned commit completed successfully in `33045740069`; its
malformed-input campaign passes with `6/6` ELF samples rejected by the real
parser.
Each current corpus sample is also compared across five deterministic
seed-derived command-line inputs.

The current all-fixture adversarial campaign covers 120 executable samples and
the `CodeVirtualization` pass. It records 600 completed tool runs, 480 explicit
unavailable-tool rows, and zero errors. Its per-pass summary records 117 applied
samples, 3 omitted samples, and no errors. The report includes radare2, objdump,
angr, Unicorn, and the custom binary analyzer; Triton, IDA Pro, Ghidra, and
Binary Ninja remain unavailable in this environment. The automated second-pass
review passes all checks and is not human sign-off.

A fresh local run on commit `4a042d6` covered all 140 executable fixtures
discovered in the current dataset. It recorded 697 completed tool runs, 560
explicit unavailable-tool rows, and 3 Unicorn errors. The per-pass result for
`CodeVirtualization` was 137 applied, 3 omitted, and 0 transformation errors,
covering 143 functions with 12 unsupported functions. The three Unicorn errors
are limited to the `vex128` fixtures and report `UC_ERR_INSN_INVALID` while
executing an AVX `vextractf128` instruction; the full sample-level evidence is
in [`docs/protection-adversarial-corpus-2026-09-01.json`](protection-adversarial-corpus-2026-09-01.json).
This run is not represented as a zero-error release gate.

The separate [`docs/protection-ghidra-corpus.json`](protection-ghidra-corpus.json)
campaign runs Ghidra headless over the same 120 original/protected pairs. It
completed 240 analyses with zero errors or timeouts and records the
`CodeVirtualization` pass summary per sample.

The current report records 600 completed tool runs and 480 explicit unavailable-
tool rows after the returning-syscall bridge and coverage extension. The focused
virtualization inventory is recorded in
[`docs/virtualization-coverage.json`](virtualization-coverage.json): 131 real
fixtures cover ten capability families with no unclassified fixture.

## 1. Current architecture

The production path audited here is `CodeVirtualizationPass` for ELF x86-64. It
has two generic lowering paths: straight-line register/FP runs and reducible or
dispatch-shaped control-flow regions. Generated VMs use per-build opcode maps,
duplicate handlers, direct-threaded encrypted dispatch, checksum-keyed operands,
scattered register frames, per-build state-mask slots, bounded frame-size variation, nested regions, and
either an existing executable-tail payload placement or a fragmented fallback.

The declared support contract is narrower than the repository's broader analysis
surface: ELF/x86-64 is the stable target; PE, Mach-O, and non-x86-64 rewriting
remain outside this pass.

## 2. Dataset coverage

`scripts/protection_maturity_baseline.py --all` discovers ELF64 `ET_EXEC` and
`ET_DYN` x86-64 files and excludes assembly sources and relocatable objects. The
current fixture inventory contains 120 compatible executable fixtures spanning
arithmetic, flags, calls, branches, switch tables, FP/SIMD, memory addressing,
PIE, red-zone, multi-exit, fallback, nested-region, dynamic-loader, and
thread-local-storage shapes.

The historical multi-seed machine-readable artifact is
[`docs/protection-maturity-corpus.json`](protection-maturity-corpus.json). Each
sample records SHA-256, size, format, architecture, function/basic-block/CFG and
instruction counts, strings, imports, references, runtime artifacts, Unicorn
exit status, and per-seed transform output hashes, sizes, timings, VM instruction
counts, and bytecode sizes. IDA/Hex-Rays evidence is recorded separately in this
ledger because the MCP adversary is an external analysis service rather than a
runtime dependency of the harness. The expanded representative evidence is in
[`docs/protection-ida-tierb.json`](protection-ida-tierb.json).
The corpus harness now requires valid emulator completion and compares native
runtime status, return code, bounded stdout/stderr digests, and created-file
manifests for every seed; stream capture and file hashing are incremental and
retain only bounded summaries.

## 3. Semantic correctness passed/failed/skipped

Correctness is measured on the real generated ELF files, not mocks. The baseline
runner executes each original and each transformed output with Unicorn until the
exit syscall and compares the observed exit code. Native host execution is
recorded on the official Linux x86-64 target and compares return code, bounded
stdout/stderr digests, and created-file manifests.

The earlier completed campaign passed `110/110` fixtures and `1100/1100` seed runs. The
targeted current-checksum and adversary regressions pass, including real calls,
FP, switch, red-zone, and multi-exit fixtures. No fixture is silently skipped by
the virtualization pass; three explicit interpreter fixtures had zero
virtualized functions for every seed and are retained as no-op coverage results.

The supported Linux path also runs a bounded three-case mutation-fuzzer campaign
against a real transformed ELF fixture. The campaign compares native exit status
and captured output through `BinaryValidator`; failure cases are not retained by
default in the repository workspace.

The continuous parser/rewriter campaign is implemented in
[`scripts/continuous_fuzz.py`](../scripts/continuous_fuzz.py) and scheduled in
GitHub Actions. The multi-analyzer evidence is in
[`docs/protection-adversarial-benchmark.json`](protection-adversarial-benchmark.json),
the full-corpus run is in
[`docs/protection-adversarial-corpus.json`](protection-adversarial-corpus.json),
and the reproducible second-pass review is in
[`docs/independent-review.json`](independent-review.json). An analyzer is marked
`unavailable` when its executable or license is absent; those rows are not
treated as passing evidence. The automated review is not human sign-off.

## 4. Obfuscation maturity technique-by-technique

| Technique | Evidence | Assessment |
|---|---|---|
| Opcode and operand polymorphism | Per-seed output hashes and bytecode sizes in corpus JSON | Effective diversity; not cryptographic secrecy |
| Handler duplication and body variation | Generated handler counts, shuffled emission, ISA/junk seeds | Raises static clustering cost |
| Direct-threaded dispatch | IDA sees per-build indirect tails as `jmp rax` or `push rax; retn` | Stronger than a plain switch; dynamic recovery remains possible |
| Checksum-keyed state | Hex-Rays recovers either a four-byte permutation or forward/reverse bytewise checksum, but not downstream keys | Integrity and key dependency are visible; traversal shape varies per build |
| Register-frame scattering | Seed-derived slot permutation and spill order | Removes fixed frame fingerprints; frame semantics remain inferable |
| Handler clustering | [`docs/protection-handler-clustering.json`](protection-handler-clustering.json): normalized nearest similarity mean `0.860`, `2,120` of `2,232` comparisons >= `0.8`, exact normalized matches `0` | The remaining similarity is shared handler structure across different operation families, not duplicate normalized bodies; changing the normalizer would be metric gaming |
| Bytecode grammar | [`docs/protection-bytecode-grammar.json`](protection-bytecode-grammar.json): target `mov`-64 handler strides change from fixed `[3]` to `[3,4,5]`; `2,566` padding bytes across `2,480` handlers. Immediate `add`/`and`/`or`/`sub`/`xor` also select one- or two-fold decompositions per build | Removes fixed record stride and adds generic arithmetic decomposition; opcode location and semantic field families remain visible |
| Anti-debug constants | Checksum-keyed constant island | No plaintext constants in representative entrypoints; runtime tracing still sees behavior |
| Fragmented RX payload | IDA segment surveys show adjacent RX loads | Adds layout work but remains fingerprintable |
| Control-flow virtualization | 120-fixture corpus and real exit-code checks | Broad synthetic semantic coverage; production format coverage is narrow |

## 5. Virtualization maturity

The current one-seed adversarial run applied the pass to 117 of 120 fixtures and records
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

Commit `868dc1f` reuses the final executable `PT_LOAD` when its file tail is
available, while retaining the fragmented fallback for images without that
geometry. On `elf_vm_arith_x86_64`, seed `20260820`, the current protected file
has two raw `PT_LOAD` entries and is `24,419` bytes versus `4,632` bytes for the
input; both emulation paths exit `45`. IDA splits the executable load into
three analysis segments and Hex-Rays still recovers the checksum loop and an
indirect `jmp rax` in the VM entry. No handler table or bytecode grammar was
recovered. This reduces the synthetic container signal without claiming that
the bootstrap is hidden.

Commit `e50bc26` selects an equivalent indirect transfer per generated decode
copy: `jmp rax` or `push rax; retn`. Fresh IDA analysis of the current
`elf_vm_arith_x86_64` build classified the VM entry as a leaf and Hex-Rays
recovered the checksum loop, encrypted offset-table load, and a final `retn`
instead of the fixed `jmp rax` tail. The table and checksum remain visible, and
no handler grammar was recovered. The real fixture retained Unicorn exit `45`.

Commit `53e8c12` adds a seed-derived reverse bytewise checksum branch across
engine, region, and nested VMs without consuming additional randomness. Fresh
IDA/Hex-Rays analysis of `elf_vm_arith_x86_64`, seed `20260820`, recovered the
reverse loop (`end - 1`, decrementing pointer) and the equivalent `push rax;
retn` transfer, but no handler table or bytecode grammar. The protected file is
`24,425` bytes versus `24,419` bytes for the preceding tail-reuse sample and
still exits `45`. The versioned observation is in
[`docs/protection-ida-checksum-direction.json`](protection-ida-checksum-direction.json).

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

The current reverse-direction representative also produced `11` correlated
dispatches, `11` unique handler targets, `11` unique bytecode positions, and
`0` raw position matches in the own adversary. Tier A remained `109/109` with
zero semantic failures; ten deterministic seeds on the arithmetic fixture
retained exit `45` and semantic equality.
The fresh audit snapshot is in
[`docs/protection-audit-20260821.json`](protection-audit-20260821.json).

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
remain green. The current reverse-direction branch adds no randomness draw and
changes the representative output by `+6` bytes; unrelated handler and junk
decisions remain stable.

## 9. Container fingerprintability

The payload container remains identifiable through a large executable tail and a
VM entry that spills many registers before the checksum. Commit `868dc1f` extends
the final executable `PT_LOAD` when the file tail is usable; the representative
raw ELF load count falls from four total loads to two, while IDA
still presents three analysis segments because it splits the original text
range. Images without a suitable final load retain the fragmented fallback.
This removes one synthetic container pattern but does not make the layout blend
into an ordinary ELF. The remaining container signal is still material.
The cave survey over all `110` compatible ELF x86-64 fixtures found `0` executable
caves of at least `256` bytes; the largest usable cave was `0` bytes. The broader
directory also contains sources and a PE fixture, but those do not establish an
ELF placement contract. Hiding the payload in existing executable space therefore
requires a new multi-region placement and relocation design.

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

The corpus artifact records transform duration, native runtime duration, Unicorn
runtime duration, and static-analysis duration for baseline and generated files.
Across 1100 runs the transform duration ranged from `0.156` to `5.680` seconds,
averaging `0.484` seconds on the official Linux x86-64 target. The checksum
variants add either a guarded four-byte permutation loop or a bytewise loop; the
latter is shorter in the representative IDA sample. Native runtime observables
are complete for every baseline and transformed run; the artifact records the
durations without treating timing as a semantic equivalence signal.

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
spill, an obvious appended executable chain, and handler bodies whose normalized
nearest similarity is `0.860` across seeds (`2120/2232` pairings remain at or
above `0.8`). Exact normalized handler matches are `0/2480`; the high nearest
similarity is therefore shared structure, not duplicate bodies. The opcode
remains at record offset zero, although per-instance tail padding now removes
the fixed record-stride assumption. The engine VM's raw vPC/base/position correlation was recovered at
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
sequence remains observable. Commit `cb41797` removes the uniform checksum
broadcast from bootstrap and handler offset tables by mixing each entry with
its index and a build-derived multiplier; the checksum loops and target sequence
remain visible.
The own devirtualizer does not support the current encrypted indirect shape, so
its negative result is not a complete adversarial benchmark. The interpreter outlier
shows that a direct handler-table architecture remains easy for Hex-Rays. Coverage
outside ELF x86-64 is not established. The strict repository quality gate now
passes without Ruff `per-file-ignores`; the repository-wide lint backlog was
resolved with explicit test assertions, named constants, and real process adapters.

Commit `868dc1f` adds a real ELF regression for extending an existing executable
tail and keeps a forced-large-gap regression for the fragmented fallback. The
one-seed Tier A rerun passed `109/109` fixtures with `0` semantic failures and
`109/109` successful runs. The full strict suite passed `4870` tests, skipped
`21`, and reached `81.03%` coverage under Python 3.12.
Commit `e50bc26` adds the per-copy indirect-transfer variation. Its focused
engine and region regressions passed, and the full strict suite retained the
same `109/109` one-seed semantic result.

## 14. Fixed

The structural resistance probe now aggregates every executable segment within a
global budget instead of measuring only the largest fragment. Symbolic analysis
imports are lazy, avoiding optional-dependency warnings. VM register save order
and frame allocation vary deterministically per build. The checksum traversal now
uses either seeded four-byte block permutations with guarded tails or a forward/
reverse bytewise walk. Each change has real
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
synthetic metadata segment while preserving the loader invariants. Commit
`868dc1f` extends a usable final executable load in place and retains the
fragmented fallback for incompatible geometry; real ELF regressions cover both
placement paths.
Commit `e50bc26` adds `push rax; retn` as an equivalent per-copy dispatch tail;
the fresh IDA survey and real exit-code regressions cover the new form.
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

Commit `400d427` randomizes the region/nested runtime state-mask slot and
records the `[rsp+220h]` IDA observation. Its full gate rerun passed `9` checks;
the only failure remains the pre-existing forbidden Ruff `per-file-ignores`
configuration, whose removal exposes the documented unsuppressed lint backlog.
Commit `d61024a` fixes the maturity harness so semantic parity requires valid
emulator completion, matching exit code, and matching bounded native-runtime
observables; the full Tier A artifact records `1090/1090` passing seed runs.
Commit `3a9ad18` removes raw instruction count from `StructuralResistance`'s
resistance score. Instruction expansion remains reported separately, while the
score uses indirect dispatches and distinct branch targets; on the real shift
fixture the measured score is `2.0` native versus `2970.0` virtualized despite
the VM's `17612` disassembled instructions.
Commit `cb41797` applies the same generic index-mixed offset-table contract to
engine and region dispatch plus bootstrap tables. The focused real suite passed
`144` tests, the full suite passed `4867` tests with `21` skips, and the one-seed
Tier A campaign passed `109/109` fixtures with `0` failed runs and matching
runtime observables. The prior ten-seed Tier A campaign remains the baseline for
the pre-existing protection contract; this change was not represented as a new
ten-seed campaign because its full rerun is materially more expensive than the
validated one-seed corpus and focused seed regressions.
An experiment that independently shuffled the three runtime-state restores in
each threaded decode copy was rejected: the ten-seed handler survey moved mean
nearest similarity from `0.8376` to `0.8401` and threshold matches from `1780` to
`1880`. The shared decode/handler template remains the dominant static signal.

## 15. Remaining gaps

The current layout, handler-tail, engine-state, and region-state changes reduce measured
signals, but the
payload still has a recognizable executable tail or fallback chain and the abstract machine remains
recognizable across builds. Further container camouflage would require a new
multi-region placement contract, not another segment or padding tweak. Stronger
semantic diversity would require alternate state encodings or instruction
decomposition across both virtualization paths, with a substantially broader
semantic oracle. Runtime tracing remains observable and resisting it requires an
execution-architecture change. Improving the current devirtualizer to understand
the encrypted threaded contract is a separate tool-capability effort. Broader
format/architecture support is outside the declared virtualization envelope.
None should be implemented as a branch for a named sample or family. The
repository-wide quality gate is green without adding lint suppression.

### Termination assessment

At code HEAD `52b6efa`, the remaining protection weaknesses require architectural
changes rather than another local polymorphism axis. The two-stage integrity
contract removes one single full-span loop, but both the short bootstrap loop and
the deferred full loop remain statically recoverable. Removing that fingerprint
requires distributing integrity state across the VM entry and threaded handlers
while preserving the encoder/checksum contract. The executable tail and fallback
chain remain ELF-container fingerprints; hiding them requires a new placement
contract that can
use multiple existing executable regions and preserve loader invariants. Runtime
traces still recover handler targets, and the raw target sequence remains
observable; reducing that exposure requires a different execution model, not more
static junk or another checksum spelling. The reverse bytewise checksum branch
is the last measured local grammar change; fresh Hex-Rays analysis still
recovers the loop, and the own adversary still recovers the target sequence
while classifying the state as encoded. Further progress requires a new
placement/execution design, so this audit records the local variation loop as
terminal rather than adding visual complexity or unmeasured bloat.

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
protected binary. The official quality wrapper was rerun at code HEAD
`3a9ad18`: 9 checks pass; the only failure is the pre-existing forbidden Ruff
`per-file-ignores` block, whose removal exposes `11,865` unsuppressed findings
(`9,632` are test assertions and `1,324` are magic-value findings).
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
Commit `400d427` randomizes the region/nested runtime state-mask slot; its
focused and Tier A evidence is recorded in `protection-state-encoding.json`.
Commit `d61024a` enforces runtime-observable parity in the maturity harness.
Commit `3a9ad18` removes raw instruction count from the structural resistance
score. Commit `ea1d1bf` removes the forbidden Ruff `per-file-ignores`, replaces
test-only lint bypasses with explicit real-test helpers, fixes symlinked driver
and shebang process execution, and passes the complete strict gate: Black, Ruff,
mypy, Bandit, pip-audit, and `pytest -W error` (`4867` passed, `21` skipped,
`81.03%` coverage under Python 3.12).
Commit `cb41797` replaces the uniform checksum broadcast used for bootstrap and
handler offset tables with a build-derived index mix. Its one-seed Tier A result
is `109/109` compatible fixtures and `109/109` successful runs with matching
runtime observables; the full strict suite passed `4867` tests, skipped `21`, and
reached `81.02%` coverage under Python 3.12.
Commit `fb3a89b` keeps logging handlers on process stdout so repeated real
validation runs do not retain closed capture streams. Commit `868dc1f` reuses
usable executable load tails for VM payloads and records the current IDA,
Tier A, and full-suite evidence above.

Commit `53e8c12` adds reverse bytewise checksum traversal, its unit regressions,
the fresh IDA/Hex-Rays artifact, and the Tier A/ten-seed evidence above.
Commit `7a2c04e` removes the unused `qiling` optional dependency and its scoped
mypy override; a dry-run resolution of `.[devirtualization]` no longer installs
the vulnerable `python-fx`/Pillow dependency chain. Static checks and direct
`pip-audit` passed after the cleanup. Two subsequent full-wrapper runs reached
clean static checks and `pip-audit` but ended with four and five real-mutation
test failures respectively; the focused virtualization/real-analysis/
real-mutation run passed `164` tests with `3` skips. A later wrapper retry was
blocked by temporary PyPI DNS failure. No test or vulnerability suppression was
introduced.
The 2026-08-21 audit refreshes the clustering artifact with `0` exact normalized
cross-seed matches and records the terminal local-variation assessment in
[`docs/protection-audit-20260821.json`](protection-audit-20260821.json).
The latest full wrapper run passed all static checks and the complete pytest
suite (`4868` passed, `21` skipped, no warnings); only `pip-audit` remained
blocked by DNS resolution for `pypi.org`.
