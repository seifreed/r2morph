<p align="center">
  <img src="https://img.shields.io/badge/r2morph-Binary%20Transformation-blue?style=for-the-badge" alt="r2morph">
</p>

<h1 align="center">r2morph</h1>

<p align="center">
  <strong>Metamorphic mutation engine with structured validation and reporting</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/r2morph/"><img src="https://img.shields.io/pypi/v/r2morph?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/r2morph/"><img src="https://img.shields.io/pypi/pyversions/r2morph?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/r2morph/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/r2morph/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/r2morph/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://codecov.io/gh/seifreed/r2morph"><img src="https://img.shields.io/codecov/c/github/seifreed/r2morph?style=flat-square" alt="Coverage"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/r2morph/stargazers"><img src="https://img.shields.io/github/stars/seifreed/r2morph?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/r2morph/issues"><img src="https://img.shields.io/github/issues/seifreed/r2morph?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**r2morph** is a metamorphic mutation engine that applies tracked binary transformations with validation, rollback, and machine-readable reports. The `0.4.0-alpha.3` support contract is intentionally narrow: Linux ELF x86-64 is the official target. Other formats and architectures remain preview or experimental.

### Key Features

| Feature | Description |
|---------|-------------|
| **Tier 1 Passes** | NOP, instruction substitution, register substitution, instruction expansion, and block reordering on the official target |
| **Declared Support** | Linux ELF x86-64; preview and experimental targets are tracked separately |
| **4 Validation Modes** | Structural, runtime, symbolic (angr), CFG integrity |
| **Analysis Cache** | Bounded filesystem cache with a background cleaner and explicit shutdown |
| **Session Management** | Checkpoint/rollback system preserving binary state across mutation passes |
| **SARIF 2.1.0 Reports** | OASIS SARIF with MITRE ATT&CK taxonomy, fingerprints, code flows |
| **JSON Reports** | Documented schema, metadata, timing, gate evaluation |
| **Detection Suite** | Packer signatures, entropy analysis, pattern matching, similarity hashing |
| **Devirtualization** | VM handler analysis, MBA simplification (Z3-based) |

---

## Installation

### Prerequisites

- Python 3.12, 3.13, or 3.14
- radare2 installed

#### Install radare2

```bash
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
```

### Install r2morph

```bash
pip install r2morph                  # Basic
pip install "r2morph[enhanced]"      # + angr, lief, z3
pip install "r2morph[all]"           # + frida, hypothesis
```

Symbolic analysis uses the Claripy implementation paired with the installed
angr release, keeping symbolic expressions compatible with angr states. The
`syntia` extra installs angr on supported platforms instead of an independently
versioned Claripy package. The supported angr extras require angr 10.0.7 or
newer and pycparser 3.11, matching angr's current parser API and Z3 dependency.
The analysis cache cleaner exits when its cache is discarded; applications can
call `cache.stop_cleanup_thread()` for deterministic shutdown.

### Development Install

```bash
git clone https://github.com/seifreed/r2morph.git
cd r2morph
python -m pip install --editable ".[dev]"
```

The CI dependency manifest remains available for reproducing the extended
analysis environment: `python -m pip install -r requirements.txt` followed by
`python -m pip install --editable .`.
CI's dependency audit uses a 60-second PyPI socket timeout to tolerate slow
responses; the audit still fails on vulnerabilities or service errors.
CI and continuous fuzzing cancel superseded main-push runs, so runners validate
the newest source revision instead of spending time on obsolete commits.
Pull requests and differential campaigns keep distinct concurrency keys where
their evidence should be retained. Adversarial campaigns serialize by ref,
allowing one active campaign and one replaceable pending run.
Release workflows remain serialized per ref. Linux x86-64 CI
installs the pinned radare2 6.2.2 Debian package after verifying its SHA-256;
other hosts retain the source-build path.
The 32-shard adversarial analyzer campaign runs at most eight shards at once
and serializes campaigns by ref, leaving runner capacity for commit validation.
The full differential corpus runs weekly or by manual dispatch; each push still
runs the general CI checks without queuing the long corpus campaign.
Cross-platform CI runs the complete unit suite on macOS and Windows for Python
3.12, 3.13, and 3.14, and on Ubuntu/Python 3.13 and 3.14. The broader
Ubuntu/Python 3.12 job also covers integration, property, and real-binary tests.
Passing these jobs expands platform evidence but does not by itself establish
full mutation parity, which remains an open release gate.
On macOS, subprocess tests pin `PYTHONHOME` to the base interpreter and
`DYLD_LIBRARY_PATH` to its runtime library directory so copied-interpreter tests
can still find the standard library.
The macOS ARM64 differential lane omits native x86-64 Mach-O execution cases;
the `macos-15-intel` CI lane runs both native x86-64 Mach-O mutation checks and
the platform evidence aggregate requires their JUnit report. The ARM64 lane's
validator rejects skips in its selected platform smoke suite.
Ubuntu workflow dependency setup retries package requests three times with
60-second connection timeouts; package-index updates and installations also
have 10- and 15-minute limits. Persistent repository failures still fail the
job instead of omitting system dependencies.
The timeout integration case uses identical temporary shell scripts so it
exercises real process timeouts without depending on copied system binaries or
their platform-specific execution rules.
The shared subprocess adapter captures standard input and output through
temporary files, avoiding pipe-closure hangs when a child leaves descendants
running while preserving complete byte output. Process-tree cleanup bounds its
final wait, so an unresponsive platform process cannot prevent the configured
process timeout from returning.
Native ABI regression failures report each program's return code and captured
output alongside the virtualization diagnostics.
If `test_virtualized_elf_preserves_floating_point_varargs_register_and_stack_abi`
fails on Ubuntu/Python 3.12, CI retains its generated C source and mutated ELF as
the `floating-point-varargs-linux-repro` artifact so the exact crash can be inspected.
When a newer commit reaches `main`, its push-triggered CI run replaces an older
in-flight push run. Manual, scheduled, and pull-request validation use separate
concurrency keys and are not replaced by main pushes.
Cross-platform unit suites emit Python stack traces after 60 seconds and the
step fails after 30 minutes, bounding a runner-specific hang. The installed-wheel
smoke also emits thread traces after 60 seconds and stops its test process after
five minutes, so hangs produce diagnostics without dropping test targets.
If the generated Clang switch-table integration case fails, CI uploads that
case's temporary C source and ELF binary for five days to make the compiler and
resolver behavior reproducible. The glob accounts for pytest shortening the
temporary directory name derived from the test function.
macOS jobs install Keystone's native shared library and expose it to Python
before collecting tests that depend on the assembler binding. The x86-64
Mach-O native smoke runs on GitHub's Intel `macos-15-intel` runner; Apple
Silicon runs the cross-platform package checks without executing x86-64 Mach-O.
Rosetta execution on Apple Silicon is not currently validated by CI.
The optional `angr` backend is not installed on Intel macOS because PyPI does
not currently publish an Intel macOS wheel; its CI coverage runs on Linux and
Apple Silicon instead.
Git checks out text with LF endings so hashes pinned to source and JSON evidence
remain stable across operating systems. Evidence paths use `/` separators on
every platform.
Windows CI verifies the documented optional-analysis fallback when angr is not
installed, and exercises validation using native Python executables rather than
POSIX shebang scripts.
CLI success notices use ASCII text so legacy Windows console encodings can
render them without a Unicode encoding failure.

---

## Support Matrix

### Formats

| Format | Status | Notes |
|--------|--------|-------|
| **ELF** | Official: Linux x86-64 | Other ELF architectures are experimental |
| **PE** | Preview/alpha | No zero-defect guarantee |
| **Mach-O** | Experimental | No zero-defect guarantee |

### Architectures

| Architecture | NOP | Substitute | Register | Expand | Block | Dead Code |
|--------------|-----|-----------|----------|--------|-------|-----------|
| **x86_64 Linux ELF** | Tier 1 | Tier 1 | Tier 1 | Tier 1 | Tier 1 | Experimental |
| **x86** | Experimental | Experimental | Experimental | Experimental | Experimental | Experimental |
| **AArch64/ARM** | Experimental | Experimental | Experimental | Experimental | Experimental | Experimental |

PE, Mach-O, ARM, and AArch64 evidence does not imply parity with Linux ELF
x86-64 or equivalent CodeVirtualization support.
Function virtualization mutation records preserve original native instruction
mnemonics even when lowering replaces them with internal VM opcodes (for example,
`xlatb` remains `xlatb` in the record rather than the VM handler key `xlat`).

The machine-readable contract is [`docs/support-matrix.json`](docs/support-matrix.json):
the generated matrix currently records 22/22 evidenced cells for the official
ELF x86-64 target (100.0% evidence) and 41/242 evidenced cells for non-official
targets (16.94% evidence). It currently classifies 5 passes as Tier 1 and
17 passes as experimental.
The installed-wheel smoke executes x86-64 Mach-O natively on Intel
`macos-15-intel` and checks instruction and register substitution against
native output. These are bounded experimental pass results; they do not
establish full Mach-O or cross-platform parity. It runs in a fresh pytest
process. Apple Silicon CI checks the installed package without claiming
Rosetta x86-64 execution coverage.
The workflow selection is covered by
[`test_macos_native_macho_smoke_runs_in_a_fresh_bounded_pytest_process`](tests/unit/test_macos_macho_smoke_workflow_contract.py).
On source `848d0f5b`, the complete native ARM64 Mach-O integration module passed
12/12 cases on macOS ARM64 with Python 3.13.11 and Clang 23.1.5, including
native-output preservation, compiled control-flow/memory fixtures, and rejection
of an unrepresentable immediate. The hash-bound
[`local report`](docs/protection-platform-macos-arm64-local-2026-11-16-848d0f5b.json)
records the source, fixture, and test hashes. This is bounded evidence from one
host and does not establish full Mach-O pass parity or cross-platform parity.
The native ARM64 Mach-O string-obfuscation smoke now passes on Apple Silicon:
it mutates an unreferenced string, preserves the referenced output string, and
verifies ad-hoc signing and runtime output. Since radare2 misses some ARM64
data xrefs, this path also scans analyzed instruction operands and fails closed
if the scan or section metadata is incomplete; file-offset operands are mapped
through section `paddr`/`vaddr` so Mach-O references are still recognized when
the image virtual address differs from its file offset. The matching Intel
x86-64 native smoke passed 3/3 cases for instruction substitution, register
substitution, and string obfuscation in
[differential workflow 45480009561](https://github.com/seifreed/r2morph/actions/runs/45480009561).
These are experimental checks, not full Mach-O or cross-platform parity; the
string-obfuscation pass does not generate runtime decode stubs. The ARM64
current-main CI result is retained in the [hash-bound smoke report](docs/protection-macho-arm64-string-2026-11-24-a4f4dcba.json)
and its [JUnit case](docs/protection-macho-arm64-string-2026-11-24-a4f4dcba.xml);
the Intel result is in its [hash-bound report](docs/protection-macho-x86-64-native-2026-11-24-a4f4dcba.json)
and [JUnit report](docs/protection-macho-x86-64-native-2026-11-24-a4f4dcba.xml).
The same workflow's six bounded platform slices passed 78/78 cases across
Mach-O ARM64/x86-64, Windows PE, and ELF ARM32/ARM64/x86-32. The
[hash-bound preview manifest](docs/protection-platform-preview-2026-11-24-45480009561.json)
links each JUnit report; this is preview evidence, not full pass-by-platform
parity.
Differential workflow run `43949336892` on source `6c60d58d` completed five
preview jobs with 76/76 cases passed: macOS ARM64 (37), Windows PE (18), ELF
ARM32 (6), ELF ARM64 (7), and ELF x86-32 (8). Their JUnit hashes are pinned in
the [`partial platform report`](docs/protection-platform-partial-run-2026-11-16-43949336892.json).
The full workflow has since completed successfully (85/85 jobs); its aggregate
confirms all five platform reports are complete, with no failures, errors, or
skips. The [`completed run report`](docs/protection-platform-completed-run-2026-11-16-43949336892.json)
pins the aggregate hash. These bounded preview cases do not establish complete
pass parity or promote preview targets to official support.
The local release validation for source commit `2c50cff3` built and installed
the `0.4.0-alpha.3` wheel on Python 3.12/macOS ARM64, passed the complete test
suite (7,006 passed, 226 skipped), validated the wheel and sdist with Twine,
and generated a vulnerability-free CycloneDX SBOM. This does not replace the
Linux release workflow, GitHub provenance attestation, current human signoff,
or the still-open 1.0 readiness gates; details and artifact hashes are in
[`docs/release-validation-local-2026-11-16-2c50cff3.json`](docs/release-validation-local-2026-11-16-2c50cff3.json).
The `9abd69e` source also built both package artifacts and passed an installed-wheel
smoke on Python 3.13.11/macOS arm64: import, CLI version, and 318 public API and
import-safety tests passed. This bounded run did not execute the full suite or
release audit; its artifact hashes and scope are recorded in
[`docs/wheel-smoke-local-2026-11-17-9abd69e9.json`](docs/wheel-smoke-local-2026-11-17-9abd69e9.json).
The `b20a56c2` release check rebuilt the current wheel and sdist, passed Twine,
repeated the installed-wheel smoke and recorded the full local suite result.
The direct `pip-audit -r requirements.txt` path could not bootstrap its
temporary environment (`ensurepip` exited with SIGABRT). Resolving the declared
requirements with `uv` into a hash-pinned macOS arm64/Python 3.13 manifest and
auditing that manifest with `pip-audit --disable-pip` passed with no known
vulnerabilities across 118 components. The pinned manifest and CycloneDX output
are recorded with their hashes; this covers that one platform resolution, not
the release workflow SBOM or other platform matrices. Provenance and Linux
release checks remain pending. See the [hash-bound local release report](docs/release-validation-local-2026-11-17-b20a56c2.json).
The latest local release check on source `5f414ed0` rebuilt the `0.4.0-alpha.3`
wheel and sdist, passed Twine, and generated a 114-component CycloneDX SBOM;
`pip-audit -r requirements.txt` found no known vulnerabilities. The full
checkout unit suite passed 5,845 tests (12 skipped), and the installed wheel
passed the 318-test package smoke. The pinned
[`local release report`](docs/release-validation-local-2026-11-20-5f414ed.json)
records artifact hashes and open limits. GitHub CI was still pending for that
source when measured; no provenance was generated and nothing was published.
The dependency resolution audit now also covers Linux x86-64 on Python 3.12 and
3.13 plus Windows x86-64 on Python 3.13, alongside the macOS arm64/Python 3.13
target. All four hash-pinned manifests passed with zero known vulnerabilities
across 442 platform-specific component entries. Linux uses the `manylinux_2_34`
resolution because the development requirements include `triton-library`; this
does not set the package's runtime glibc floor. Manifests, SBOMs, hashes, and
scope limits are in the [dependency audit matrix](docs/dependency-audit-matrix-2026-11-17-51ab5ffb.json).
On source `49279456`, the standalone release-contract check passed and all 158
release-contract/readiness tests passed under Python 3.13.17/macOS arm64 with
the local Keystone and angr dependencies available. This verifies the current
alpha contract and confirms the three stable-major blockers remain enforced; it
does not build a release or complete the stable-release gates. See the
[hash-bound check record](docs/release-contract-check-local-2026-11-24-49279456.json).
The scheduled extended maturity smoke now records output-size,
transform-duration, runtime-duration, and static metric summaries for every
selected pass. The same summary now records 0 with no independent
false-positive measurement,
0 with no independent decompiler-effectiveness measurement,
0 without contractual composition support, and no remaining affected-instruction catalogue gap.
The reproducible GCC/Clang corpus and its build manifest live in the public
[`r2morph-corpus`](https://github.com/seifreed/r2morph-corpus) repository.
The successful 85-job differential workflow for source commit `b20a56c2`
measured 360 compatibility samples, 10/10 corpus passes, 12/12 extended
maturity passes, and 48 VM semantic-contract shards. It found no differential
failures in its Linux x86-64 ELF scope; transformations omitted for ineligible
samples are counted in the reports. Licensed decompiler checks were omitted,
and PE, Mach-O, x86, ARM, and AArch64 remain outside this run's scope, so these
results do not close the analyzer or cross-platform gates. The hash-checked
compressed reports and precise counts are recorded in
[`docs/differential-run-2026-11-17-44081385675-summary.json`](docs/differential-run-2026-11-17-44081385675-summary.json).
VM semantic campaign rows that cannot virtualize any function retain the
rejected function and instruction diagnostics, including capability and
reason, so unsupported fixtures can be traced to a concrete blocker. Computed
jump diagnostics distinguish a disabled feature from an enabled dispatch that
the current analysis could not prove. If radare2 omits switch edges, dispatch
lifting also gathers resolved case blocks in the same executable section,
bounded by the next known function start; unresolved and out-of-range targets
remain rejected. A masked switch index bounds table reading only when the mask
and indirect jump share a basic block and no intervening instruction changes
that index. Linux integration coverage compiles a dense 16-case Clang `-O2`
switch with in-function arithmetic destinations, asserts that the analyzer
resolves exactly 16 table entries, and requires full VM virtualization with
native output parity.
The same differential workflow passed again on current source commit `1cf52005`
in run [44213229027](https://github.com/seifreed/r2morph/actions/runs/44213229027).
Its 85 jobs completed successfully; artifacts report zero failures or errors
across 5,540 core differential classifications, 7,572 extended-maturity
classifications, 2,450 VM-semantic tests, 1,288 composition tests, and 1,728
differential-fuzz cases. Supplemental cross-format smoke reported 2,146 cases,
including 290 skipped cases. These bounded results do not close cross-platform,
named-analyzer, or resistance gates; Binary Ninja remains unavailable without a
valid license. See the [current-run evidence summary](docs/differential-run-2026-11-18-44213229027-summary.json).

### Instruction Equivalence Rules

- **x86/x86_64**: 100+ rules in `x86_rules.yaml` - bidirectional groups covering zero registers, self-moves, flag-preserving patterns, XOR/SUB equivalence
- **ARM32**: 10+ groups in `arm_rules.yaml` - zero, increment, decrement, self-move, shift, negate, double, compare for r0-r11
- **ARM64**: Register classes defined in `arm64_rules.yaml`

---

## Mutation Passes

### Tier 1 (official target)

| Pass | CLI Flag | Description |
|------|----------|-------------|
| **NOP Insertion** | `-m nop` | Replaces redundant instructions with benign equivalents; in x86-64 it excludes 32-bit self-moves because those zero-extend the destination register |
| **Instruction Substitution** | `-m substitute` | Replaces instructions with semantically equivalent alternatives |
| **Register Substitution** | `-m register` | Substitutes registers via liveness analysis |
| **Instruction Expansion** | `-m expand` | Expands supported instructions into validated equivalent sequences |
| **Block Reordering** | `-m block` | Reorders eligible basic blocks with validated jump repair |

The x86-64 ELF and native macOS Mach-O NOP smoke fixtures use `mov rax, rax`
for a redundant self-move candidate; `mov eax, eax` is intentionally
ineligible because it zero-extends into RAX.

### Experimental (working, limited testing)

| Pass | Surface | Description |
|------|----------|-------------|
| **Dead Code Injection** | engine-only | Injects semantically neutral code in padding regions |
| **Control Flow Flattening** | engine-only | Inserts opaque predicates and jump obfuscation |
| **Opaque Predicates** | engine-only | Writes opaque predicate instructions into basic blocks; reuses function-boundary disassembly during cave searches within a pass |
| **Code Virtualization** | engine-only | Translates instructions to VM bytecode with dispatcher |
| **Anti-Disassembly** | engine-only | Injects anti-disassembly snippets |
| **Data Flow Mutation** | engine-only | Data flow analysis-driven safe substitutions |
| **Short Jump Patching** | engine-only | Patches short jumps to equivalent sequences |
| **Constant Unfolding** | engine-only | Unfolds constant expressions into multi-instruction equivalents |
| **Code Mobility** | engine-only | Relocates blocks to code caves with trampolines |
| **Function Outlining** | engine-only | Distributes function chunks across code caves |
| **API Hashing** | engine-only | Hash trampolines obscuring PLT references |
| **Import Obfuscation** | engine-only | Jump stub indirection for import calls |
| **Self-Modifying Code** | engine-only | XOR-encrypts function bodies with runtime decryptor |
| **Stack Strings** | engine-only | Rebuilds string literals on the stack at runtime |
| **String Obfuscation** | engine-only | Encodes unreferenced string data; referenced strings are unchanged |
| **Pattern Substitution** | engine-only | Applies size-preserving byte-pattern substitutions |
| **Polymorphic Engine** | engine-only | Orchestrates iterative experimental mutation passes |

Seeded engine handlers can use equivalent structural forms for byte-field loads
(`movzx` or zero-then-byte-load) and XMM memory moves (`movups` or `movdqu`).
Both forms preserve guest-visible flags. This expands generated handler shapes;
it is not a resistance guarantee, and cross-seed similarity measurements remain
bounded evidence.

The experimental region VM lowers register-form BMI2 `shlx` and immediate
form `rorx` while preserving guest flags. It also supports VEX.128 memory-form
`vmovd` loads, register-form `vpinsrd`, XMM `vpbroadcastd`/`vpbroadcastq`, and
VEX.128 immediate byte shifts (`vpsrldq`).
Linux x86-64 integration fixtures check native results; the BMI2 fixture also
checks condition flags and requires a BMI2-capable CPU. These instruction-level
results do not establish general SIMD coverage or close the broader VM
compatibility and resistance gates.

The ELF x86-64 direct-call target decoder uses scratch registers that preserve
the System V `AL` vector-argument count. The native Linux floating-point varargs
integration fixture exposed an offset undercount for VEX scalar arithmetic
bytecode; the shared size table and an encoder-size regression test now cover
that case. Linux CI installs GDB so the fixture can capture registers and the
faulting instruction on a signal failure. The ABI release gate remains open
until the native integration job passes; this fixture does not establish general
varargs or ABI parity.

---

## Validation

| Mode | Flag | Status | Description |
|------|------|--------|-------------|
| **Structural** | `--validation-mode structural` | Stable | Binary format integrity checks (always runs) |
| **Runtime** | `--validation-mode runtime` | Stable | Compares original vs mutated execution (exit code, stdout, stderr, files) |
| **Symbolic** | `--validation-mode symbolic` | Experimental | Bounded symbolic step via angr (ELF x86_64, advisory) |
| **CFG Integrity** | Automatic | Experimental | Reachability and edge preservation checks |

Real-binary CI smoke tests retain each utility's original basename when saving its
mutated copy, so multicall system binaries continue dispatching the tested applet.

Native x86-64 Mach-O integration checks run on Intel macOS. Apple Silicon
execution through Rosetta remains experimental and is not covered by CI.

The experimental `BinaryRewriter` applies size-preserving instruction
replacements only when the virtual address maps to file-backed bytes in an
executable section and the original bytes still match. Short replacements are
padded with assembled NOP instructions to complete instruction boundaries.
The x86-64 ELF integration fixture checks a size-neutral equivalent instruction
replacement and compares native process results on Linux x86-64.
Insertions, deletions, relocations, and section growth are rejected; these
operations need format-aware relocation and metadata handling before they can
be reported as supported. A no-patch rewrite copies the input bytes exactly.
The continuous-fuzz `binary_rewriter` target also applies bounded byte-level
replacements and checks stale-byte rejection and that surrounding bytes remain
unchanged; it does not fuzz complete executable semantics.

The scheduled and manually dispatched differential corpus runs `--passes all`, `--require-applied`, and
`--require-complete-evidence`; complete evidence covers runtime, output size,
transform duration, runtime duration, and static analyzer evidence while
comparing exit code, stdout, stderr, created files, and declared observable
effects across nine seed-derived inputs.
The 48 shard/seed jobs retain those distinct corpus measurements and the
extended-pass maturity runs. The fixed cross-format, composition, VM semantic,
and fuzz regression smokes run once per campaign because they use the same
inputs in every shard; their aggregate requires and validates each resulting
artifact before publishing the campaign.

The current-source local stress run on commit `4fbe86fb` exercised all ten
parser, assembler, VM, relocation, and binary-rewriter fuzz targets 10,000
times each with generated payloads capped at 32 KiB and zero failures. Its
source and raw-report hashes, seed, diagnostics, and limits are recorded in the
[`bounded fuzz evidence manifest`](docs/continuous-fuzz-local-2026-11-17-4fbe86fb.json).
This single-host deterministic run does not prove arbitrary-input semantic
equivalence, cross-platform parity, or adversarial resistance.

A second local run on commit `0491ba06` exercised the same ten targets 5,000
times each with payloads capped at 4 KiB and zero failures. The current-source
manifest and raw report are pinned in
[`docs/continuous-fuzz-local-2026-11-18-0491ba06.json`](docs/continuous-fuzz-local-2026-11-18-0491ba06.json).
This bounded macOS ARM64 run adds current-source fuzz evidence; it does not
establish cross-platform parity or adversarial resistance.

The main-push continuous-fuzz workflow on source `5519152b` passed on Ubuntu,
macOS 15, and Windows after building and installing the wheel. Each platform
ran 5,000 cases for each of ten parser, assembler, VM, relocation, and rewriting
targets (150,000 target runs total), using a fixed seed and payloads capped at
4 KiB. All three reports record zero failures and 103
`macho_load_commands.warning` diagnostics. The summary includes hashes for the
canonical JSON reports and the original workflow artifacts at
[`docs/continuous-fuzz-2026-11-19-44425946598-summary.json`](docs/continuous-fuzz-2026-11-19-44425946598-summary.json).
This bounded campaign does not test transformed-program equivalence and does
not establish exhaustive fuzz coverage, full platform parity, or adversarial
resistance.

The continuous-fuzz workflow on source `749131c6` passed on Ubuntu, macOS 15,
and Windows after building and installing the wheel: 5,000 cases for each of
the same ten targets per platform (150,000 target runs total), with zero
failures and 4 KiB payload limits. The three raw reports and their
source-bound hashes are recorded in
[`docs/continuous-fuzz-2026-11-19-44562397087-summary.json`](docs/continuous-fuzz-2026-11-19-44562397087-summary.json).
This deterministic bounded campaign does not establish exhaustive fuzz
coverage, transformed-program equivalence, complete platform parity, or
adversarial resistance.

A further main-branch run on source `b5612378` used seed `20261119` and passed
the same ten targets on Ubuntu, macOS 15, and Windows: 5,000 cases per target
and platform (150,000 target runs total), with zero failures. Each platform
retained 101 recoverable `macho_load_commands.warning` diagnostics. Its raw
reports, artifact hashes, and limits are pinned in
[`docs/continuous-fuzz-2026-11-19-44613330309-summary.json`](docs/continuous-fuzz-2026-11-19-44613330309-summary.json).
This deterministic bounded campaign does not establish exhaustive fuzz
coverage, transformed-program equivalence, full platform parity, or adversarial
resistance.

The next main-push fuzz run on source `d363ed86` also passed on Ubuntu,
macOS 15, and Windows: 5,000 cases for each of the same ten targets per
platform (150,000 target runs total), with zero failures and 103 recoverable
`macho_load_commands.warning` diagnostics. Its reports and artifact hashes are
pinned in
[`docs/continuous-fuzz-2026-11-19-44631018926-summary.json`](docs/continuous-fuzz-2026-11-19-44631018926-summary.json).
This bounded campaign does not prove arbitrary-input semantic equivalence,
exhaustive fuzz coverage, complete platform parity, or adversarial resistance.

The current-source fuzz run on `a61f599e` completed on Ubuntu, macOS 15, and
Windows using the installed wheel: 5,000 deterministic cases for each of ten
parser, assembler, VM, relocation, and rewrite targets per platform (150,000
target runs total), with zero failures and 103 recoverable
`macho_load_commands.warning` diagnostics per platform. The source commit,
artifact digests, raw reports, and limits are pinned in
[`docs/continuous-fuzz-2026-11-24-45416536037-summary.json`](docs/continuous-fuzz-2026-11-24-45416536037-summary.json).
This bounded campaign does not prove arbitrary transformed-program
equivalence, exhaustive fuzz coverage, complete platform parity, or
adversarial resistance.

On source commit `92ff809c`, a local macOS ARM64 run passed 5,000 cases for
each of the same ten fuzz targets (50,000 target runs total), with zero
failures and 107 recoverable `macho_load_commands.warning` diagnostics. The
Python 3.13.17 environment, source and report hashes, and limits are pinned in
[`docs/continuous-fuzz-local-2026-11-24-92ff809c.json`](docs/continuous-fuzz-local-2026-11-24-92ff809c.json)
and its [raw report](docs/continuous-fuzz-local-2026-11-24-92ff809c-report.json).
This one-host bounded campaign does not prove transformed-program equivalence,
full platform parity, exhaustive fuzz coverage, or adversarial resistance.

The Continuous Fuzzing workflow then passed on source commit `92ff809c` across
Ubuntu, Windows, and macOS 15: 5,000 cases for each of ten targets per platform
(150,000 target runs total), with zero failures and 103 recoverable
`macho_load_commands.warning` diagnostics per platform. The three reports,
workflow artifact IDs and digests, source hash, and scope limits are pinned in
[`docs/continuous-fuzz-2026-11-24-45460386121-summary.json`](docs/continuous-fuzz-2026-11-24-45460386121-summary.json).
The campaign does not establish transformed-program equivalence, exhaustive
fuzz coverage, full product parity, or adversarial resistance.

The next main-push fuzz run on source `5f5078f7` also passed on Ubuntu,
macOS 15, and Windows: 5,000 cases for each of the same ten targets per
platform (150,000 target runs total), with zero failures and 103 recoverable
`macho_load_commands.warning` diagnostics per platform. Its three compressed
reports, workflow artifact IDs and hashes, source hash, and limits are pinned
in [`docs/continuous-fuzz-2026-11-20-44646998764-summary.json`](docs/continuous-fuzz-2026-11-20-44646998764-summary.json).
This bounded deterministic campaign does not establish exhaustive fuzz
coverage, transformed-program equivalence, complete platform parity, or
adversarial resistance.

The next main commit's differential workflow (`44308008537`) failed its
aggregate check because independently built corpus shards repeated fixture and
seed rows. The previous size-weighted shard assignment could change when
generated binary sizes differed between workers. Shards now use stable,
count-balanced ordering by unique fixture name in
[`scripts/maturity_fixture_sharding.py`](scripts/maturity_fixture_sharding.py).
This removes the cross-worker assignment drift; the workflow still needs to
verify the fix, and count-balanced shards can have runtime skew.

On the same source commit, the differential workflow completed 85 jobs:
10,860 core and 13,032 extended classifications had complete evidence and
zero failures. The cross-platform fuzz workflow completed 150,000 target runs
across Ubuntu, Windows, and macOS with zero failures. The 362-fixture
adversarial benchmark completed 55,220 of 71,676 analyzer rows; Binary Ninja
and IDA Pro were unavailable, and 528 Unicorn rows lacked instruction support.
These results are bounded to the documented corpora and do not close platform
parity or resistance. The aggregate and raw-artifact hashes are recorded in
[`current-main-validation-2026-11-18-0491ba06.json`](docs/current-main-validation-2026-11-18-0491ba06.json).
The main CI run passed 11 jobs but was cancelled during four macOS package
smoke jobs, so those jobs remain unverified. Its automated review passed 28
checks but still records human signoff as `not-attested`.

The 2026-11-20 main-push fuzz run
[`44656133058`](https://github.com/seifreed/r2morph/actions/runs/44656133058)
passed on source `6dec0392` on Linux, macOS, and Windows: 5,000 deterministic
cases for each of ten parser, assembler, VM, relocation, and rewriting targets
per platform (150,000 target runs total), with zero failures. The three platform
reports and source/run hash manifest are recorded in
[`continuous-fuzz-2026-11-20-44656133058-summary.json`](docs/continuous-fuzz-2026-11-20-44656133058-summary.json).
Each platform retained 103 recoverable Mach-O parser diagnostics. This bounded
campaign does not prove arbitrary-input equivalence, full platform parity, or
adversarial resistance. Each generated VM bytecode case also verifies that the
checksum and position mask preserve the terminal exit opcode.

The next main-push run on source `09db9ea2` also passed all three platforms and
ten targets: 5,000 cases per target and platform (150,000 target runs total),
with zero failures. Its `binary_rewriter` target exercises byte replacement,
stale-byte rejection, and preservation outside the patch range. The reports,
artifact IDs, and hashes are pinned in
[`continuous-fuzz-2026-11-20-44667500653-summary.json`](docs/continuous-fuzz-2026-11-20-44667500653-summary.json).
This bounded campaign does not validate complete executable semantics or close
the compatibility, differential, or adversarial-resistance gates.

The following main-push run on source `a3359d66` also passed on all three
platforms and ten targets: 5,000 cases per target and platform (150,000 target
runs total), with zero failures. The `binary_rewriter` target now traverses the
rewriter's virtual-address-to-file-offset mapping and checks rejection of
stale bytes, out-of-file addresses, and non-executable sections. Reports,
artifact IDs, and hashes are pinned in
[`continuous-fuzz-2026-11-20-44668686404-summary.json`](docs/continuous-fuzz-2026-11-20-44668686404-summary.json).
It uses bounded synthetic section data and does not fuzz complete executable
semantics or output-file integration.

The 2026-11-20 dispatched run on source `2f54c47e` passed on Ubuntu, macOS 15,
and Windows: 5,000 cases for each of the same ten targets per platform
(150,000 target runs total), with zero failures and 96 recoverable
`macho_load_commands.warning` diagnostics per platform. The raw reports,
workflow artifact IDs and hashes, source hash, and limits are pinned in
[`continuous-fuzz-2026-11-20-44676210319-summary.json`](docs/continuous-fuzz-2026-11-20-44676210319-summary.json).
This bounded campaign uses synthetic rewriter section data and does not prove
complete executable equivalence, exhaustive fuzz coverage, or complete
platform parity.

The latest main-push run
[`44683267033`](https://github.com/seifreed/r2morph/actions/runs/44683267033)
passed on source `24d68c8c` across macOS 15, Ubuntu, and Windows after building
and installing the wheel. It completed 5,000 cases for each of ten parser,
assembler, VM, relocation, and rewriting targets per platform (150,000 target
runs total) with zero failures. Each report retained 103 recoverable Mach-O
parser diagnostics. The source-bound manifest and reports are in
[`continuous-fuzz-2026-11-20-44683267033-summary.json`](docs/continuous-fuzz-2026-11-20-44683267033-summary.json).
This bounded campaign does not establish arbitrary-input equivalence,
exhaustive fuzz coverage, complete platform parity, or adversarial resistance.
Windows report files retain their original line endings so the manifest hashes
continue to match the downloaded artifact bytes.

The previous differential workflow
[`44661095783`](https://github.com/seifreed/r2morph/actions/runs/44661095783)
captured a partial snapshot on `f319f1e4`: four platform targets passed 39/39
selected cases; one of 16 core shards recorded 230 classified runs with 76
applied transformations and 100% complete evidence; its extended shard
recorded 276/276 complete-evidence runs across all 12 extended passes. Eleven
VM semantic shards passed 461/461 fixture-seed cases. The overall workflow
later failed in its macOS ARM64 differential smoke and aggregate gate, so the
snapshot is partial evidence only. The hash-bound
[snapshot and reports](docs/protection-differential-partial-2026-11-20-44661095783/summary.json)
preserve the captured artifact IDs, hashes, and limits. The later run
[`44669121610`](https://github.com/seifreed/r2morph/actions/runs/44669121610)
failed because NOP insertion had no safe candidate in any corpus fixture and
the aggregate platform contract omitted the separate Intel macOS run. The
fixture and aggregate contract have since been corrected. The completed
workflow [`44676092171`](https://github.com/seifreed/r2morph/actions/runs/44676092171)
passed all 86 jobs on its pinned source commit `2f54c47e`: 10,860 core and
13,032 extended classifications had complete evidence with zero failures or
errors. Its generated public compatibility corpus passed 360 samples across
six passes, and the 46-case composition smoke ran in all 48 jobs (2,208
executions) with zero failures or errors. This is
bounded evidence for that source revision; platform parity, named-analyzer
coverage, and published resistance criteria remain open. Counters, artifact
hash, and scope limits are pinned in the
[`run summary`](docs/differential-run-2026-11-20-44676092171-summary.json).

The 2026-11-24 differential run `45418027212` exposed a compile defect in the
pinned public corpus's `avx_packed_compare.c`: its memory helper accepted a
`const float *` but received a `__m256`. The workflow now applies the tracked
correction in
[`r2morph-corpus-avx-packed-memory.patch`](.github/patches/r2morph-corpus-avx-packed-memory.patch)
and fails if any expected compiler/build variant or source family is omitted.
The corrected public corpus passed its four-shard aggregate in run
[`45428767299`](https://github.com/seifreed/r2morph/actions/runs/45428767299)
on source `acafac289598b2ca22ec66498873ccfba4775bd3`: 370 samples across six
selected passes, zero differential failures, and 2,220 complete static
recovery measurements with zero failures. The hash-bound result is recorded in
[`public-compatibility-corpus-2026-11-24-45428767299.json`](docs/public-compatibility-corpus-2026-11-24-45428767299.json).
The latest completed current-source differential run, [`45480009561`](https://github.com/seifreed/r2morph/actions/runs/45480009561)
on source `a4f4dcba`, passed all 86 jobs. Its Linux ELF x86-64 core matrix
classified 10,860 runs across ten passes (3,480 applied and 7,380 omitted);
the extended matrix classified 13,032 runs across twelve passes (3,406 applied
and 9,626 omitted). Both have complete evidence for every row and zero errors
or semantic failures. The same run passed the 46-case composition smoke in all
48 jobs (2,208 executions), a 370-sample
public corpus with 2,220 successful radare2 recovery measurements, 1,005/1,005
VM fixture-seed cases with all QEMU pairs matching, and 78/78 bounded platform
preview cases. Its [hash-bound manifest](docs/differential-run-2026-11-24-45480009561.json)
records artifact IDs, report hashes, and scope. The run still records 22
decompiler maturity blockers; omitted transformations are not passes. This
evidence does not close full platform parity, all-named-analyzer coverage, or
general adversarial resistance.

A local current-main rerun on 2026-11-19 used Python 3.14.10 on macOS ARM64 and
recorded 50,000 target runs (5,000 for each of the same ten fuzz targets), zero
failures, and 103 recoverable Mach-O parser diagnostics. Its report and
source-bound manifest are
[`continuous-fuzz-local-2026-11-19-670a07d6.json`](docs/continuous-fuzz-local-2026-11-19-670a07d6.json).
This single-host bounded run supplements the platform workflow; it does not
establish cross-platform parity or adversarial resistance.

The 2026-09-20 local adversarial campaign measures all 162 repository fixtures:
`angr` completed 162/162 runs, while radare2, objdump, and the custom analyzer
also completed all runs. Unicorn completed 155/162 runs; its seven unavailable
rows are retained with their instruction-support reasons. In that campaign,
IDA and Triton were unavailable; these rows remain explicit and are not counted
as completed analysis. Ghidra is provisioned by the scheduled campaign. The bounded
report is
[`docs/protection-adversarial-angr-local-2026-09-20.json`](docs/protection-adversarial-angr-local-2026-09-20.json).
The earlier focused `angr` fixture remains available in
[`docs/protection-adversarial-angr-local-2026-09-18-59898697.json`](docs/protection-adversarial-angr-local-2026-09-18-59898697.json).
That focused fixture records 5 completed analyzer slots and 4 unavailable analyzer slots.
Binary Ninja is an explicit analyzer slot; the focused local
fixture records `binary-ninja` as unavailable because `module 'binaryninja' is unavailable`.
The current installed API is importable, but the headless benchmark reports
`analyzer license is unavailable`; this remains an explicit evidence gap while
the slot is on hold. The 2026-11-14 adversarial campaign summary records 362
samples across 22 passes, with `7964 completed Ghidra tool runs` and
`7964 completed Triton tool runs`; Binary Ninja, IDA Pro, and some Unicorn rows
remain unavailable. The separate 159-sample IDA MCP campaign records
`159 samples, 318 completed analyses` and `159 samples, 0 IDA errors`. These
are campaign-specific results: availability in one campaign does not fill unavailable rows in another,
and the all-named-analyzers 1.0 criterion remains open. See
[`docs/protection-adversarial-run-2026-11-14-43615553431.json`](docs/protection-adversarial-run-2026-11-14-43615553431.json).

A subsequent workflow run on source commit `6c60d58d` completed all 33 jobs and
recorded the same 362-sample, 22-pass corpus: 7,964/7,964 pass rows and
71,676/71,676 analyzer rows were present, with zero missing rows or execution
errors. Only 55,220 analyzer rows completed (77.04%); Binary Ninja and IDA Pro
were unavailable in the workers, and Unicorn did not support 528 fixture rows.
The hash-bound [run manifest](docs/protection-adversarial-run-2026-11-16-43952405619.json)
and [compressed raw report](docs/protection-adversarial-run-2026-11-16-43952405619.json.gz)
retain the evidence. The analyzer gate remains open.

A bounded local rerun on source commit `dedfef14` covered two repository-fixture
shards (8 distinct ELF x86-64 fixtures) across all 22 passes. IDA Pro 9.5
completed all 176 analyzer rows for those fixtures; across 1,584 analyzer slots,
1,056 completed and 528 were unavailable (Binary Ninja, Ghidra, and Triton).
There were no pass/tool errors or missing rows. The macOS run excludes generated
Linux fixtures, and the all-analyzer gate remains open. Hash-bound reports and
fixture hashes are listed in
[`docs/compatibility-corpus.md`](docs/compatibility-corpus.md#current-source-local-ida-shards).

A focused rerun on source commit `12eb478e` measured `CodeVirtualization` on
`elf_vm_shift_x86_64`: one function was virtualized with no partial or unsupported
functions. The automated pair report completed `angr`, `custom`, `objdump`,
radare2, and Unicorn without tool errors; Unicorn returned 42 for both original
and protected files. Binary Ninja, Ghidra headless, IDA headless, and Triton were
unavailable in that runner, so those slots remain open. A separate IDA MCP
analysis of the same fixture and recorded seed completed on both files: IDA
counted two functions in the original and four in the protected file, whose entry
decompilation showed a checksum loop. This single-sample observation is not a
semantic-equivalence or generalized-resistance result. The [automated report](docs/protection-adversarial-current-main-2026-11-19-12eb478e.json)
and [IDA pair record](docs/protection-ida-current-main-2026-11-19-12eb478e.json)
retain the measurements and unavailable slots.

The follow-up Ghidra 11.4.2 slice on source commit `8a612589` measured
`CodeVirtualization` on four repository fixtures: Ghidra completed 4/4 rows,
while six of nine analyzers completed overall (24/36 rows). IDA Pro timed out
on four rows; Binary Ninja was unavailable due to license status, and Triton
was not installed. The source and fixture hashes, decompiler deltas, and raw
report are recorded in
[`docs/compatibility-corpus.md`](docs/compatibility-corpus.md).
This bounded output comparison does not demonstrate generalized resistance;
all-analyzer, cross-platform parity, and resistance gates remain open.

A current-source local rerun on 2026-11-20 used Ghidra 12.2 on the 162
repository fixtures at source commit `716dcfac`. All 324 original/protected
analyses completed without errors or timeouts; the function count changed in
151 pairs and stayed the same in 11. CodeVirtualization applied to all 162
fixtures and virtualized 170 functions, with no unsupported or partial
virtualization. Function-count changes are only a coarse analyzer observation,
not proof of semantic preservation or resistance. The hash-bound
[raw report](docs/protection-ghidra-corpus-2026-11-20-716dcfac.json) and
[summary](docs/protection-ghidra-corpus-2026-11-20-716dcfac-summary.json)
preserve scope and provenance; analyzer, parity, and resistance gates remain
open.

The completed differential workflow on that source revision also retained a
360-build public ELF x86-64 corpus: 19,440 differential inputs passed across six
passes, with 713 transformations applied and 1,447 omitted. Five platform
slices completed 76 selected smoke cases without failures. Optional decompiler
runners were not configured, so these results do not close analyzer coverage,
broader pass-by-platform compatibility, or resistance. The hash-bound workflow
evidence is summarized in
[`docs/compatibility-corpus.md`](docs/compatibility-corpus.md#published-differential-workflow-evidence-2026-11-17).
Another adversarial campaign, run `44050933385` on source commit `8a612589`,
returned success for all 32 shard jobs across 362 ELF x86-64 fixtures and 22
passes. It recorded 7,964 pass rows and 71,676 analyzer slots: 55,220 completed,
16,456 unavailable, and zero error or missing rows. Ghidra and Triton completed
all rows; Binary Ninja and IDA were unavailable on the workers, and Unicorn
could not handle 528 rows. The VM smoke reports cover 10 seeds and 15 fixtures;
they record semantic parity and divergent tamper probes, while progressive
bytecode growth was supported on only 6 fixtures. Similarity remained high for
some handlers (388/2,295 comparisons exceeded 0.8; maximum 0.927). The reports
mark human adversarial review as pending; the aggregate job later completed
successfully (job `133987828440`). This bounded evidence does
not establish generalized resistance. See the hash-bound
[`campaign summary`](docs/protection-adversarial-2026-11-17-44050933385-summary.json)
and [shard reports](docs/protection-adversarial-2026-11-17-44050933385.tar.gz);
analyzer and resistance gates remain open.
The current-source campaign,
[`44142495055`](https://github.com/seifreed/r2morph/actions/runs/44142495055),
completed all 32 shards on `b656b0dc`, covering 362 ELF x86-64 samples and 22
passes. It observed all 7,964 pass rows and 71,676 analyzer rows; 55,220
(77.04%) completed, with zero errors or missing rows. Six analyzer slots had
full coverage; Unicorn completed 7,436 rows and could not execute 528; Binary
Ninja and IDA Pro were unavailable for all rows. The automated VM smoke covered
15 fixtures over ten seeds; semantic parity, diversity, and tamper-probe checks
passed, while progressive bytecode growth was supported on six fixtures and
388/2,295 cross-seed comparisons exceeded 0.8 similarity. This bounded evidence
does not establish generalized resistance. The independent automated review
passed 28 checks, but Marc Rivero Lopez's human approval remains bound to
`a111f923` and does not cover later production changes. See the
[hash-bound summary](docs/protection-adversarial-2026-11-18-44142495055-summary.json),
[complete reports](docs/protection-adversarial-2026-11-18-44142495055.tar.gz),
[review record](docs/protection-independent-review-run-2026-11-18-44166019050.json),
and [regression test](tests/unit/test_published_adversarial_campaign_44142495055.py).
The all-analyzer and published-resistance gates remain open.
On source `6d8d450a`, a local one-fixture `CodeVirtualization` measurement
completed IDA Pro decompilation for both the original and protected ELF, and
Unicorn returned the same exit code (45). Six of nine analyzer slots completed;
Binary Ninja was unavailable for lack of a license, while Ghidra and Triton were
unavailable in this local environment. This is one sample, not analyzer-matrix
coverage. See the [hash-bound report](docs/protection-adversarial-current-main-local-2026-11-18-6d8d450a.json),
[summary](docs/protection-adversarial-current-main-local-2026-11-18-6d8d450a-summary.json),
and [regression tests](tests/unit/test_published_local_adversarial_current_main_6d8d450a.py).
An expanded local shard on source `9112e77f` measured all 22 configured passes
across four ELF x86-64 repository fixtures. It recorded 88/88 pass rows and
528/792 completed analyzer rows with no pass/analyzer errors or missing rows;
Binary Ninja, Ghidra, and Triton were unavailable. angr emitted unsupported VEX
and CCall diagnostics, so its completed rows do not establish full decompiler
coverage. The generated Linux corpus was not run on this macOS host. This is
bounded analyzer evidence, not generalized resistance; see the [hash-bound
summary](docs/protection-adversarial-current-main-2026-11-18-9112e77f-shard-0-summary.json)
and [compressed report](docs/protection-adversarial-current-main-2026-11-18-9112e77f-shard-0.json.gz).
On source `7cb29ce1`, the next local shard covered four more fixtures and all 22
passes (88 pass rows, 528/792 analyzer rows completed, zero errors or missing
rows; eight passes applied). The same three tools remained unavailable locally.
See the [hash-bound summary](docs/protection-adversarial-current-main-2026-11-18-7cb29ce1-shard-1-summary.json)
and [compressed report](docs/protection-adversarial-current-main-2026-11-18-7cb29ce1-shard-1.json.gz).
This is partial analyzer evidence; both analyzer completeness and resistance
remain open.
The complete analyzer workflow on source `1cf52005` covered 362 fixtures (200
generated), 22 passes, 7,964 pass rows, and 71,676 analyzer slots: 55,220 rows
completed with no errors or missing rows. Ghidra and Triton completed every
row; Binary Ninja and IDA Pro were unavailable, and Unicorn reported 528
unsupported rows. Its separate 15-fixture, ten-seed VM smoke still requires
human adversarial review. See the [hash-bound summary](docs/protection-current-production-adversarial-2026-11-18-44223496306-summary.json)
and [shard/VM archive](docs/protection-current-production-adversarial-2026-11-18-44223496306.tar.gz).
Analyzer completeness and general resistance remain open.
The current automated report records `human_signoff: not-attested` and
`release_decision: block-vm-milestone`, because the production tree changed
after the reviewed commit `a111f923df43a66826b71ab70db8a484532fbf3b`. Human
independent review approved the reviewed commit only. The project owner
confirms Marc Rivero Lopez's independence and specialist experience in binary
rewriting and virtualization. He reviewed memory, direct/indirect calls,
returns, flags, FP/SIMD, varargs/ABI,
unwinding, TLS/signals, SSA, and liveness paths; unsupported instructions must
fail closed instead of producing partial protected functions. Diagnostics
include instruction address, mnemonic, type, size, bounded opcode preview,
capability, and reason. The review covered VM ISA/opcode diversification,
dispatcher/handler alternatives, superinstructions, anti-tamper, and progressive
bytecode protection, fuzz properties, failure handling, and bounded report
data. This approval applies to that commit only; stable release validation now
requires a review of the final production tree, with a separate signoff-only
commit.
Current VM resistance artifacts cover 10 seeds with 255 handlers per seed,
0 exact normalized cross-seed handler matches, 0 exact normalized within-seed
handler matches, normalized nearest similarity mean 0.652 (328/2,295
comparisons at or above 0.8; maximum 0.933), and 12 handler stride values,
documenting target handler stride diversity.
These finite seed-diversity measurements describe generated output variation;
they do not measure generalized attack cost or establish resistance to
professional reverse engineering. The reports are
[`docs/protection-handler-clustering.json`](docs/protection-handler-clustering.json)
and [`docs/protection-bytecode-grammar.json`](docs/protection-bytecode-grammar.json).
The independent analysis report explicitly
limits its evidence to one fixture and one pass and states that it does not
establish general resistance to professional reverse engineering. The report
does not replace the required three-analyzer release campaign. Published
resistance results remain an open 1.0 criterion.

On source `5b7b566a`, a 100-seed follow-up measured generated handler templates:
all 100 opcode assignments were unique, with zero within-seed duplicate
handlers, but 38 exact normalized handler matches appeared across seeds (19
pairs). The [hash-bound summary](docs/protection-vm-handler-diversity-local-2026-11-19-5b7b566a-100seeds-summary.json)
and [raw report](docs/protection-vm-handler-diversity-local-2026-11-19-5b7b566a-100seeds.json)
record this template-only measurement; they do not measure execution or
analyst attack cost, so the resistance gate remains open.

After adding seeded byte-load and SIMD move forms, the same 100-seed range on
source `c6a124a2` measured 32 normalized cross-seed handler matches in 16
pairs, down from 38; within-seed matches remained zero. The
[hash-bound summary](docs/protection-vm-handler-diversity-local-2026-11-20-c6a124a2-100seeds-summary.json)
and [raw report](docs/protection-vm-handler-diversity-local-2026-11-20-c6a124a2-100seeds.json)
record the result. This is a measured reduction, not zero-collision evidence or
a claim of generalized resistance; the gate remains open.

An audit found that five older local VM resistance reports counted 720 missing
native tamper observations as divergent. Those historical tamper claims are
retracted; their hash-bound files remain unchanged, and the resistance gate
stays open. New measurements distinguish `completed`, `partial`, and
`unavailable` tamper evidence and represent unknown divergence as `null`. See
the [correction ledger](docs/vm-resistance-metric-correction-2026-11-20.json)
and its [regression test](tests/unit/test_vm_resistance_metric_correction.py).

---

## Quick Start

```bash
# Mutate with stable passes
r2morph mutate input.elf -o output.elf -m nop -m substitute -m register

# SARIF report for CI/CD
r2morph mutate input.elf -o output.elf --format sarif --report mutations.sarif

# Reproducible run
r2morph mutate input.elf -o output.elf --seed 1337

# Runtime validation
r2morph validate original.elf mutated.elf --corpus fixtures/dataset/runtime_corpus.json

# CI gate: fail if severity below threshold
r2morph mutate input.elf -o output.elf --report report.json --min-severity bounded-only

# Display and filter reports
r2morph report report.json --only-pass nop --summary-only
r2morph report report.json --format sarif -o report.sarif
```

---

## CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `r2morph mutate` | Apply mutations, validate, export binary + report |
| `r2morph validate` | Compare original vs mutated binary behavior |
| `r2morph report` | Display, filter, or convert a saved report |
| `r2morph analyze` | Analyze binary structure and functions |
| `r2morph functions` | List functions in a binary |
| `r2morph version` | Show version |

### Report Filters

| Filter | Purpose |
|--------|---------|
| `--format <json\|sarif>` | Output format (JSON default, SARIF 2.1.0) |
| `--only-pass <name>` | Restrict to one mutation pass |
| `--only-mismatches` | Show only symbolic observable mismatches |
| `--only-failed-gates` | Show only failed severity gates |
| `--only-degraded` | Show only degraded validation modes |
| `--summary-only` | Print textual triage summary only |
| `--output <file>` | Export filtered JSON |
| `--require-results` | Exit 1 when filtered view is empty |
| `--min-severity <sev>` | Require minimum severity in view |

---

## Observability

r2morph writes human-readable development logs to stderr and selects
newline-delimited JSON automatically when
`R2MORPH_ENVIRONMENT=production`. Levels, file rotation, correlation,
redaction, and event conventions are documented in
[Logging and observability](docs/observability.md).

```bash
R2MORPH_ENVIRONMENT=production R2MORPH_LOG_FILE=./r2morph.jsonl \
  r2morph mutate sample.bin -o sample.mutated
```

---

## SARIF 2.1.0 Integration

Reports in SARIF format include:

- **MITRE ATT&CK taxonomy** - T1027 (Obfuscated Files), T1027.001 (Binary Padding), T1027.002 (Software Packing)
- **Partial fingerprints** (SHA256) for deduplication across CI runs
- **Code flows** showing mutation chains per function
- **Related locations** linking mutations to validation failures
- **Disassembly snippets** in the rendered field alongside hex bytes
- **Fix suggestions** with byte-level replacements

Compatible with GitHub Code Scanning, Azure DevOps, SonarQube, and any SARIF 2.1.0 consumer.

---

## Python API

```python
from r2morph import MorphEngine
from r2morph.mutations import NopInsertionPass, InstructionSubstitutionPass, RegisterSubstitutionPass

with MorphEngine() as engine:
    engine.load_binary("input.elf").analyze()

    engine.add_mutation(NopInsertionPass())
    engine.add_mutation(InstructionSubstitutionPass())
    engine.add_mutation(RegisterSubstitutionPass())

    result = engine.run(validation_mode="structural", report_path="report.json")
    engine.save("output.elf")

print(f"Applied {result['total_mutations']} mutations")
```

---

## Detection & Analysis

| Module | Capability |
|--------|-----------|
| **Obfuscation Detector** | Commercial packer signatures (VMProtect, Themida, UPX, etc.), confidence scoring |
| **Entropy Analyzer** | Section entropy analysis for packing/encryption detection |
| **Pattern Matcher** | Anti-debug, anti-VM, string encryption, import hiding detection |
| **Similarity Hasher** | Fuzzy hashing for binary comparison (ssdeep-style) |
| **Control Flow Detector** | CFF, opaque predicates, VM dispatch, MBA expression detection |
| **Packer Signatures** | 50+ categorized signature database |

## Devirtualization (Experimental)

| Module | Status | Notes |
|--------|--------|-------|
| **VM Handler Analyzer** | Working | Pattern-based handler classification |
| **MBA Solver** | Working | Z3 SMT solver, max 8 variables, timeout-bounded |
| **CFO Simplifier** | Framework | Pattern library defined, application incomplete |
| **Binary Rewriter** | Framework | Patch/relocation infrastructure |

## Instrumentation (Experimental)

Frida integration for dynamic analysis: process spawning, script injection, API call logging, anti-analysis detection. Requires `frida` package.

---

## Report Schema

JSON reports follow a documented schema at `r2morph/reporting/report_schema.json`. Each report includes:

- **metadata**: tool version, timestamp, duration, platform
- **input/output**: binary path, architecture, format, function count
- **passes**: per-pass mutation counts, timing, diff summaries
- **mutations**: flat list with address, bytes, disassembly, function, section
- **validation**: mode, results, symbolic coverage
- **gate_evaluation**: severity gate outcomes for CI
- **summary**: aggregated statistics

---

## Requirements

- Python 3.10+
- radare2
- Optional: `lief` (PE/Mach-O/section creation), `angr` (symbolic validation), `frida` (instrumentation), `z3-solver` (MBA simplification)

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support the Project

If you find r2morph useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Attribution Required:**
- Author: **Marc Rivero** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/r2morph](https://github.com/seifreed/r2morph)

---

<p align="center">
  <sub>Made with dedication for the reverse engineering community</sub>
</p>
