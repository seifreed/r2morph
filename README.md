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
| **Session Management** | Checkpoint/rollback system preserving binary state across mutation passes |
| **SARIF 2.1.0 Reports** | OASIS SARIF with MITRE ATT&CK taxonomy, fingerprints, code flows |
| **JSON Reports** | Documented schema, metadata, timing, gate evaluation |
| **Detection Suite** | Packer signatures, entropy analysis, pattern matching, similarity hashing |
| **Devirtualization** | VM handler analysis, MBA simplification (Z3-based) |

---

## Installation

### Prerequisites

- Python 3.12 or 3.13
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
On `main`, an in-flight general CI run is allowed to finish. GitHub keeps at
most one pending run for the same concurrency group, and a newer push can
replace that pending run so checks follow the latest source. Dedicated fuzzing,
differential, and adversarial evidence runs keep their own concurrency policies.
The full differential corpus runs weekly or by manual dispatch; each push still
runs the general CI checks without queuing the long corpus campaign.
Cross-platform CI runs the complete unit suite on macOS and Windows for Python
3.12 and 3.13, and on Ubuntu/Python 3.13. The broader Ubuntu/Python 3.12 job
also covers integration, property, and real-binary tests. Passing these jobs
expands platform evidence but does not by itself establish full mutation
parity, which remains an open release gate.
The timeout integration case uses identical temporary shell scripts so it
exercises real process timeouts without depending on copied system binaries or
their platform-specific execution rules.
The shared subprocess adapter captures standard input and output through
temporary files, avoiding pipe-closure hangs when a child leaves descendants
running while preserving complete byte output.
Native ABI regression failures report each program's return code and captured
output alongside the virtualization diagnostics.
If `test_virtualized_elf_preserves_floating_point_varargs_register_and_stack_abi`
fails on Ubuntu/Python 3.12, CI retains its generated C source and mutated ELF as
the `floating-point-varargs-linux-repro` artifact so the exact crash can be inspected.
An in-flight push-triggered CI run is allowed to finish when later commits reach
`main`, preserving the complete cross-platform validation result for that active
run. A newer push can replace a run that is still pending.
The installed-wheel cross-platform smoke emits Python thread traces after 60
seconds and stops the test process after five minutes, so runner-specific hangs
produce bounded diagnostics without dropping test targets.
macOS jobs install Keystone's native shared library and expose it to Python
before collecting tests that depend on the assembler binding.
Apple Silicon jobs install and verify Rosetta before running the native
x86-64 Mach-O smoke tests.
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

The machine-readable contract is [`docs/support-matrix.json`](docs/support-matrix.json):
the generated matrix currently records 22/22 evidenced cells for the official
ELF x86-64 target (100.0% evidence) and 40/242 evidenced cells for non-official
targets (16.53% evidence). It currently classifies 5 passes as Tier 1 and
17 passes as experimental.
The macOS differential workflow also executes x86-64 Mach-O under Rosetta and
checks applied instruction substitution, register substitution, and instruction
expansion against native output. These are bounded experimental pass results;
they do not establish full Mach-O or cross-platform parity. The installed-wheel
smoke runs the native x86-64 Mach-O tests in a fresh pytest process, separately
from unrelated integration tests that can initialize native helper threads.
On ARM64 macOS the test executes each x86-64-only binary directly, allowing
macOS to dispatch it through Rosetta while keeping it in the process group
managed by the per-command timeout. The isolated test process also has a
two-minute limit. The workflow
selection is covered by
[`test_macos_native_macho_smoke_runs_in_a_fresh_bounded_pytest_process`](tests/unit/test_macos_macho_smoke_workflow_contract.py).
On source `848d0f5b`, the complete native ARM64 Mach-O integration module passed
12/12 cases on macOS ARM64 with Python 3.13.11 and Clang 23.1.5, including
native-output preservation, compiled control-flow/memory fixtures, and rejection
of an unrepresentable immediate. The hash-bound
[`local report`](docs/protection-platform-macos-arm64-local-2026-11-16-848d0f5b.json)
records the source, fixture, and test hashes. This is bounded evidence from one
host and does not establish full Mach-O pass parity or cross-platform parity.
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
The dependency resolution audit now also covers Linux x86-64 on Python 3.12 and
3.13 plus Windows x86-64 on Python 3.13, alongside the macOS arm64/Python 3.13
target. All four hash-pinned manifests passed with zero known vulnerabilities
across 442 platform-specific component entries. Linux uses the `manylinux_2_34`
resolution because the development requirements include `triton-library`; this
does not set the package's runtime glibc floor. Manifests, SBOMs, hashes, and
scope limits are in the [dependency audit matrix](docs/dependency-audit-matrix-2026-11-17-51ab5ffb.json).
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
| **NOP Insertion** | `-m nop` | Inserts benign NOP equivalents at safe locations |
| **Instruction Substitution** | `-m substitute` | Replaces instructions with semantically equivalent alternatives |
| **Register Substitution** | `-m register` | Substitutes registers via liveness analysis |
| **Instruction Expansion** | `-m expand` | Expands supported instructions into validated equivalent sequences |
| **Block Reordering** | `-m block` | Reorders eligible basic blocks with validated jump repair |

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
| **String Obfuscation** | engine-only | Encodes string data behind runtime reconstruction |
| **Pattern Substitution** | engine-only | Applies size-preserving byte-pattern substitutions |
| **Polymorphic Engine** | engine-only | Orchestrates iterative experimental mutation passes |

The ELF x86-64 direct-call target decoder uses scratch registers that preserve
the System V `AL` vector-argument count. The native Linux floating-point varargs
integration fixture still fails with `SIGSEGV` in CI while the equivalent
x86-64 emulated run passes. Linux CI installs GDB so the fixture can capture
registers and the faulting instruction on a signal failure. This ABI release
gate remains open, and the fixture does not establish general varargs or ABI
parity.

---

## Validation

| Mode | Flag | Status | Description |
|------|------|--------|-------------|
| **Structural** | `--validation-mode structural` | Stable | Binary format integrity checks (always runs) |
| **Runtime** | `--validation-mode runtime` | Stable | Compares original vs mutated execution (exit code, stdout, stderr, files) |
| **Symbolic** | `--validation-mode symbolic` | Experimental | Bounded symbolic step via angr (ELF x86_64, advisory) |
| **CFG Integrity** | Automatic | Experimental | Reachability and edge preservation checks |

On Apple Silicon, native x86-64 Mach-O integration checks explicitly launch through Rosetta
with `arch -x86_64`; this validates x86-64 execution and does not claim native ARM64 execution.

The scheduled and main-push differential corpus runs `--passes all`, `--require-applied`, and
`--require-complete-evidence`; complete evidence covers runtime, output size,
transform duration, runtime duration, and static analyzer evidence while
comparing exit code, stdout, stderr, created files, and declared observable
effects across nine seed-derived inputs.

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

The current `main` wheel also passed the continuous fuzz workflow on Linux,
macOS, and Windows: 5,000 deterministic cases for each of ten parser,
assembler, VM, relocation, and rewriting targets per platform (150,000 target
runs total), with zero failures. The three platform reports and their source/run
hash manifest are recorded in
[`continuous-fuzz-2026-11-16-43949336376-summary.json`](docs/continuous-fuzz-2026-11-16-43949336376-summary.json).
Each platform retained 103 recoverable Mach-O parser diagnostics. This bounded
campaign does not prove arbitrary-input equivalence, full platform parity, or
adversarial resistance. Each generated VM bytecode case also verifies that the
checksum and position mask preserve the terminal exit opcode.

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
The follow-up Ghidra 11.4.2 slice on source commit `8a612589` measured
`CodeVirtualization` on four repository fixtures: Ghidra completed 4/4 rows,
while six of nine analyzers completed overall (24/36 rows). IDA Pro timed out
on four rows; Binary Ninja was unavailable due to license status, and Triton
was not installed. The source and fixture hashes, decompiler deltas, and raw
report are recorded in
[`docs/compatibility-corpus.md`](docs/compatibility-corpus.md).
This bounded output comparison does not demonstrate generalized resistance;
all-analyzer, cross-platform parity, and resistance gates remain open.
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
handler matches, 12 handler stride values, and
target handler stride diversity recorded in
[`docs/protection-handler-clustering.json`](docs/protection-handler-clustering.json)
and [`docs/protection-bytecode-grammar.json`](docs/protection-bytecode-grammar.json).
These finite seed-diversity measurements describe generated output variation;
they do not measure generalized attack cost or establish resistance to
professional reverse engineering. The independent analysis report explicitly
limits its evidence to one fixture and one pass and states that it does not
establish general resistance to professional reverse engineering. The report
does not replace the required three-analyzer release campaign. Published
resistance results remain an open 1.0 criterion.

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
