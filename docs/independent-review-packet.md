# Independent Review Packet

This packet defines the human review required before the current virtualizer
milestone can be marked complete. It is intentionally unsigned: automated
checks are evidence, not a human approval.

## Target

- Commit: `fa5cbf0`
- Production evidence baseline: `9ac3e14`.
- Scope: ELF x86-64 CodeVirtualization, VM diversification, analyzer corpus,
  and dispatcher/relocation/rewriter fuzzing.
- Binary Ninja: measured by the benchmark when its licensed API is available;
  unavailable environments retain an explicit non-passing row.

## Evidence

- [`compatibility-corpus.md`](compatibility-corpus.md)
- [`test_code_virtualization_generic_isa_real.py`](../tests/integration/test_code_virtualization_generic_isa_real.py)
- [`protection-adversarial-corpus-2026-09-06-aad4aeb9-triton.json`](protection-adversarial-corpus-2026-09-06-aad4aeb9-triton.json)
- [`protection-adversarial-corpus-2026-09-06-de3111e4.json`](protection-adversarial-corpus-2026-09-06-de3111e4.json)
- [`protection-adversarial-corpus-2026-09-06-dbf77c59-triton.json`](protection-adversarial-corpus-2026-09-06-dbf77c59-triton.json)
- [`protection-adversarial-corpus-2026-09-06-01b50ea-triton.json`](protection-adversarial-corpus-2026-09-06-01b50ea-triton.json)
- [`protection-adversarial-corpus-2026-09-05-44bca563-triton.json`](protection-adversarial-corpus-2026-09-05-44bca563-triton.json)
- [`protection-adversarial-corpus-2026-09-05-a92e8b9-triton.json`](protection-adversarial-corpus-2026-09-05-a92e8b9-triton.json)
- [`protection-adversarial-corpus-2026-09-05-fa85d18-triton.json`](protection-adversarial-corpus-2026-09-05-fa85d18-triton.json)
- [`protection-adversarial-corpus-2026-09-05-c820685f-triton.json`](protection-adversarial-corpus-2026-09-05-c820685f-triton.json)
- [`protection-ida-mcp-corpus-2026-09-06-a7512ec5.json`](protection-ida-mcp-corpus-2026-09-06-a7512ec5.json)
- [`protection-ida-mcp-corpus-2026-09-06-a7512ec5-summary.json`](protection-ida-mcp-corpus-2026-09-06-a7512ec5-summary.json)
- [`protection-ghidra-corpus-2026-09-04-88258a05.json`](protection-ghidra-corpus-2026-09-04-88258a05.json)
- [`protection-adversarial-corpus-2026-09-05-83e6eee6-triton.json`](protection-adversarial-corpus-2026-09-05-83e6eee6-triton.json)
- [`protection-fuzz-2026-09-06-1c84fc56.json`](protection-fuzz-2026-09-06-1c84fc56.json)
- [`protection-fppackedidxnb-ida-2026-09-06-702450d7.json`](protection-fppackedidxnb-ida-2026-09-06-702450d7.json)
- [`protection-fppackedidxnb-ida-2026-09-06-a3b8c6e.json`](protection-fppackedidxnb-ida-2026-09-06-a3b8c6e.json)
- [`protection-ida-mcp-corpus-2026-09-06-702450d7.json`](protection-ida-mcp-corpus-2026-09-06-702450d7.json)
- [`protection-fuzz-2026-09-06-cf44477.json`](protection-fuzz-2026-09-06-cf44477.json)
- [`protection-adversarial-corpus-2026-09-06-38bee7f.json`](protection-adversarial-corpus-2026-09-06-38bee7f.json)
- [`protection-adversarial-corpus-2026-09-06-38bee7f-summary.json`](protection-adversarial-corpus-2026-09-06-38bee7f-summary.json)
- [`protection-adversarial-corpus-2026-09-06-bc2bff2.json`](protection-adversarial-corpus-2026-09-06-bc2bff2.json)
- [`protection-adversarial-corpus-2026-09-06-bc2bff2-summary.json`](protection-adversarial-corpus-2026-09-06-bc2bff2-summary.json)
- [`protection-adversarial-corpus-2026-09-06-43ba227c.json`](protection-adversarial-corpus-2026-09-06-43ba227c.json)
- [`protection-adversarial-corpus-2026-09-06-43ba227c-summary.json`](protection-adversarial-corpus-2026-09-06-43ba227c-summary.json)
- [`protection-adversarial-corpus-2026-09-06-6de7999e-triton.json`](protection-adversarial-corpus-2026-09-06-6de7999e-triton.json)
- [`protection-adversarial-corpus-2026-09-06-c0ceaaa6-triton.json`](protection-adversarial-corpus-2026-09-06-c0ceaaa6-triton.json)
- [`protection-adversarial-corpus-2026-09-06-a727f304.json`](protection-adversarial-corpus-2026-09-06-a727f304.json)
- [`protection-ida-mcp-corpus-2026-09-06-6de7999e.json`](protection-ida-mcp-corpus-2026-09-06-6de7999e.json)
- [`protection-ida-mcp-corpus-2026-09-06-6de7999e-summary.json`](protection-ida-mcp-corpus-2026-09-06-6de7999e-summary.json)
- [`independent-review.json`](independent-review.json)
- [`../scripts/check_release_contract.py`](../scripts/check_release_contract.py)
- [`../tests/unit/test_release_contract.py`](../tests/unit/test_release_contract.py)

The current `de3111e4` evidence records 159/159 virtualized samples, 171 virtualized
functions, zero unsupported functions, zero partial virtualizations, 939
completed analyzer runs, 15 Unicorn baseline errors, and 80,000 fuzz target
  runs. Triton and angr complete all 159 pairs. The latest detailed IDA MCP
corpus rerun, at `6de7999e`, contains 318 completed analyses with zero errors; Ghidra
remains represented by the completed 318-analysis report listed above.
For the named regression `elf_vm_fppackedidxnb_x86_64`, the bounded evidence
records one virtualized function, zero unsupported/partial functions, native
exit `6 -> 6`, IDA with `1/2` functions and zero errors, and Triton with `8/8`
original instructions semantically supported. Binary Ninja is measured by the
benchmark when its licensed API is available; older artifacts that predate
that integration remain historical evidence only.
The automated review still reports `human_signoff: not-attested`.
The current-state IDA MCP rerun for the named regression is recorded in the
`a3b8c6e` artifact: one original function, nine protected functions, and zero
analysis errors. Native ELF execution was not attempted on macOS.
The current CodeVirtualization corpus rerun records 15 explicit Unicorn
errors and 318 local IDA/Ghidra-unavailable rows; these are not attributed to
Triton or angr. Binary Ninja availability is now recorded by the adversarial
benchmark rather than excluded as a project decision. The full six-pass rerun
remains documented separately with its explicit unavailable-tool rows.
The `bc2bff2` rerun was performed after making partial virtualization fail
closed by default; the explicit `reject_partial_virtualization=False` override
is retained only for regression reproduction. The pushed CI workflow
`34028851868` for commit `a7512ec5` completed successfully across the full
matrix. The local Python 3.13 run completed 5531 tests with 123 expected skips
and 81.01% coverage after this default-policy change. CI state is not used as
human approval.

The current `a727f304` rerun preserves LSDA call-site mappings in VM unwind
metadata. It records 159/159 CodeVirtualization applications, 171 virtualized
functions, zero unsupported or partial virtualizations, 939 completed analyzer
runs, 15 isolated Unicorn errors, and 318 explicit local IDA/Ghidra-unavailable
rows. Angr and Triton complete every original/protected pair. Binary Ninja is
measured when its licensed API is present and otherwise recorded as
unavailable. Human signoff remains `not-attested`.
The pushed CI workflow `34065194410` completed successfully across its Linux,
macOS, and Windows matrix, including installed-wheel smoke tests, typecheck,
lint, integration, and property/fuzz validation.
The fixture inventory covers 150 ELF x86-64 virtualization fixtures across all
10 declared capability categories, with no unclassified fixtures; the
repository contains 65 focused virtualization integration modules. This is
coverage evidence, not a claim of universal ISA support.

The current automated review rerun for `94ead726` passes all 11 checks, including
the 264-cell support matrix and the existing 159-sample virtualization corpus.
The target history extends the compiler-generated ELF regression outside that
corpus to GCC fixed-load `-O0`, `-O1`, `-O2`, `-O3`, and `-Os`, GCC fixed-load
`-O2` with frame pointers, GCC PIE `-O2`, GCC stripped fixed-load `-O2`, and
Clang fixed-load `-O2`; the Linux CI integration job virtualizes its generic
GP, shift, and memory mix in all nine C images, three scalar floating-point
images, two packed SSE2 images, and three call-graph images and
preserves the native exit code, stdout, and stderr. The same job also builds
five arbitrary C++ ELF variants with structured `switch`/loop control flow
using GCC `-O0`, `-O2`, `-O3`, and `-Os`, plus Clang++ `-O2`, and verifies the
native result after virtualization. The generated instruction mix exercises
integer operations and comparisons through `imul`, `neg`, `not`, `cmp`,
`sete`, and `movzx`, as well as carry consumption and rotate round-trips
through `stc`, `adc`, `clc`, `sbb`, `rol`, and `ror`. CI run `34173770557`
completed successfully across the configured matrix.
The same rerun reports `human_signoff: not-attested`; this packet therefore
remains technically updated but not human-approved. The release contract at
this commit also validates that the packet and compatibility documentation do
not contain broken local Markdown links. Release `v0.4.0-alpha.1` is published
with wheel, source archive, SBOM, checksums, and verified provenance; this is
release evidence, not human approval.

The published `v0.4.0-alpha.1` release gate was rerun on 2026-09-08. The
release `SHA256SUMS` manifest verifies the wheel, source archive, and SBOM;
their SHA-256 values are `f175db70c2b176949d7d07bc7a5329c3b111bb0573f768f4bc9db956055666bb`,
`1a08e4ea9ac6872b463f43210ffb486c257a4fab64dbaef8e31488f054de3bb9`, and
`61ea1a117bb453782243b8ada1495a259e3bc7e1764074be96c777827fefc78e`,
respectively. GitHub attestation verification passes for all three release
artifacts. A fresh Python 3.13 isolated environment installs the wheel from
the release, imports `r2morph` as `0.4.0-alpha.1`, and reports
`r2morph 0.4.0-alpha.1` from the CLI. The repository release contract also
passes its current documentation-link and counter checks.

The current target also adds a real PE x86-64 regression outside the stable
ELF contract. The test compiles an arbitrary PE fixture, executes the original
and NOP-mutated images with the same exit code, and verifies repaired PE
checksum and integrity. The local test passes and the full CI run
`34173770557` validated the integration suite. Its only failed job was a
transient macOS radare2 checkout caused by DNS resolution; rerun
`34174862496` completed the full matrix successfully. PE remains
preview-only.

The current target also adds a real Mach-O arm64 execution regression. On
macOS, the test compares the original fixture with the NOP-mutated fixture,
re-signing the mutated image ad hoc because the original code signature is
invalidated by modification; exit code, stdout, and stderr remain identical.
The local ARM64/Mach-O regression tests pass, and CI run `34177508565`
completed the full matrix successfully. Mach-O and ARM64 remain experimental.

The current target fixes a semantic defect exposed by executing ARM64
instruction substitution on the real Mach-O fixture. The previous replacement
encoded `add w0, wzr, 0` as an operation using `wsp`, changing the process exit
code to `224`; the replacement now uses an `orr` form with `wzr`/`xzr` and
rejects immediates that cannot be represented by that encoding. The unit and
native regression tests pass (`9 passed`), and CI run `34180345005` completed
the full matrix successfully. This closes the tested immediate-substitution
case; ARM64 instruction and binary coverage remains experimental and
incomplete outside this fixture and encoding subset.

The current target extends that evidence with two arbitrary ARM64 Mach-O
executables compiled from C at test time. A representable `return 3` is
mutated and preserves its native exit code; an unrepresentable `return 37`
is rejected without mutation and preserves execution. The focused ARM64
integration module passes `7/7`, and CI run `34182601293` completed the full
matrix successfully. It also adds an arbitrary compiled ARM64 executable with
volatile memory, conditional control flow, arithmetic, division, and XOR; the
substitution pass applies two mutations across two functions and preserves the
native exit code. The focused module passes `8/8`, and CI run `34185103592`
completed the full matrix successfully.
The same generated ARM64 executable now includes an explicit redundant
instruction so the NOP pass is exercised on the arbitrary memory/control-flow
path as well; it applies a real mutation and preserves the native exit code.
The focused module passes `9/9`, and CI run `34189480116` completed the full
matrix successfully. ARM64 remains experimental.

The current target strengthens the PE preview evidence with a generated
x86-64 executable whose mutated function performs volatile memory access,
conditional control flow, arithmetic, and division before the redundant
instruction is rewritten. The original and mutated images both exit with
code `0`; checksum repair and PE integrity validation pass before and after
mutation. The local regression passes and CI run `34187173363` completed the
full matrix successfully. PE remains preview-only.
The current target also adds native PE substitution coverage on a generated
arbitrary executable with the same memory and control-flow mix. The pass
applies real substitutions, checksum repair and integrity validation pass,
and the mutated image preserves exit code `0`. The focused PE module passes
`2/2`, and CI run `34192212419` completed the full matrix successfully.

The current target also fixes ARM64 register substitution for 32-bit register
spellings. Candidate selection now preserves `wN` versus `xN` width, chooses
substitutes deterministically, and the generated native ARM64 regression is
restricted to macOS where the Mach-O compiler and executor are available. The
focused ARM64 contract passes `25/25` locally; CI run `34196695434` completed
the full configured matrix successfully, including typecheck, integration,
core, installed-wheel, and platform jobs. ARM64 remains experimental.

The current target records the generated ARM64 register-substitution evidence
in the exhaustive support matrix. The Mach-O/AArch64 cell is marked
`evidenced`, while the platform remains experimental and outside the official
Linux ELF x86-64 guarantee. The matrix still contains 264 explicit cells and
the automated review continues to require human signoff.

The current target also adds a regression contract that rejects `supported`
status for every non-official format or architecture. PE, Mach-O, ARM, and
AArch64 may carry explicit evidence, but remain outside the official target.

The current target adds native PE x86-64 register-substitution evidence. A
compiler-generated executable is run before and after mutation under Wine;
the focused PE module passes `3/3`, and checksum repair plus PE integrity
validation pass after mutation. PE remains preview-only.

## Reproduction

Run from the repository root with the pinned Python 3.13 environment:

```bash
source /private/tmp/r2morph-venv313/bin/activate
python scripts/independent_review.py --output /tmp/independent-review.json
python -m pytest -q --no-cov tests/unit/test_independent_review_contract.py tests/unit/test_adversarial_benchmark_contract.py
```

The reviewer should compare the generated report with the committed reports,
then inspect the implementation and regression tests rather than relying on
the aggregate counters alone.

## Human checklist

- [ ] Confirm the `elf_vm_fppackedidxnb_x86_64` regression is generic and not
      sample-specific.
- [ ] Inspect memory, direct/indirect calls, returns, flags, FP/SIMD,
      varargs/ABI, unwinding, TLS/signals, SSA, and liveness paths.
- [ ] Confirm unsupported instructions fail closed and cannot silently produce
      a partial protected function.
- [ ] Review VM ISA/opcode diversification, dispatcher/handler alternatives,
      superinstructions, anti-tamper, and progressive bytecode protection.
- [ ] Review the fuzz properties and failure handling for dispatcher,
      relocations, and rewriting.
- [ ] Check that reports contain bounded metadata rather than raw sample bytes
      or analyst host paths.
- [ ] Record any finding with a reproducer, severity, and affected commit.

## Sign-off

### Agent review record

Reviewer: Codex (AI coding agent)
Date (UTC): 2026-09-08
Result: TECHNICAL REVIEW RECORDED; HUMAN APPROVAL NOT ATTESTED
Reviewed commit: `fa5cbf0`
Independence statement: This is an AI-assisted repository review, not a
human independent review or approval. The reviewer has no authority to attest
human independence on behalf of a person.

```text
Reviewer:
Affiliation:
Date (UTC):
Independence statement:
Result: APPROVE / APPROVE WITH FINDINGS / REJECT
Findings:
Reviewed commit: fa5cbf0
```

No approval is implied until a human reviewer fills this section outside the
automated test process.
