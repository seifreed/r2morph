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

**r2morph** is a mutation-first engine for applying metamorphic binary transformations with explicit validation, rollback, and machine-readable reports. It leverages **radare2** and **r2pipe** to analyze binaries, apply tracked mutations, and verify the result before export.

### Key Features

| Feature | Description |
|---------|-------------|
| **Tracked Mutations** | Every mutation is recorded with address, original/mutated bytes, disassembly, and function context |
| **Validation Pipeline** | Structural, runtime, and experimental symbolic validation with automatic rollback on failure |
| **Session Management** | Checkpoint/rollback system preserving binary state across mutation passes |
| **SARIF 2.1.0 Reports** | Full OASIS SARIF output with MITRE ATT&CK taxonomy, fingerprints, and code flows for CI/CD integration |
| **JSON Reports** | Machine-readable reports with metadata, timing, gate evaluation, and JSON Schema documentation |
| **CLI + Python API** | Run as `morph`, `mutate`, `validate`, `report`, or embed as a library |
| **radare2-backed Analysis** | CFG, SSA, liveness, dataflow, and register tracking via radare2/r2pipe |
| **Detection Suite** | Packer signature database, entropy analysis, control flow pattern detection, similarity hashing |
| **Devirtualization** | VM handler analysis, MBA simplification (Z3-based), CFO pattern removal |

---

## Installation

### Prerequisites

- Python 3.10+
- radare2 installed

#### Install radare2

```bash
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
```

### Install r2morph

```bash
# Basic installation
pip install r2morph

# Enhanced analysis capabilities
pip install "r2morph[enhanced]"

# All optional features
pip install "r2morph[all]"
```

### Development Install

```bash
git clone https://github.com/seifreed/r2morph.git
cd r2morph
pip install -e .

# Dev tooling
pip install -e ".[dev]"
```

---

## Product Focus

`r2morph` is being focused around a single product:

**load binary -> apply tracked mutations -> validate -> export binary + report**

The stable core is mutation + validation. Advanced reversing workflows remain available in the repository, but are secondary and should be treated as experimental.

See [docs/ROADMAP.md](docs/ROADMAP.md) for the implementation roadmap and current phase status.

## Support Matrix

### Stable Core

| Area | Supported | Notes |
|------|-----------|-------|
| **Formats** | ELF | Full section handling, relocation support |
| **Architectures** | x86_64 | Comprehensive instruction equivalence rules |
| **Architectures** | x86 (32-bit) | Partial support via shared register maps |
| **Mutations** | `nop`, `substitute`, `register` | Fully tested, production-ready |
| **Validators** | `structural`, `runtime` | Structural always runs; runtime via `--validation-mode runtime` |
| **Output** | JSON + SARIF 2.1.0 | `--format json` (default) or `--format sarif` |

### Experimental / Working

| Area | Supported | Notes |
|------|-----------|-------|
| **Mutations** | `expand` | Single-instruction expansions, flag-safe subset |
| **Mutations** | `block` | Basic block reordering with jump patching |
| **Mutations** | `dead-code` | Injects dead code in padding regions |
| **Mutations** | `short-jump` | Patches short jumps to equivalent sequences |
| **Mutations** | `constant-unfolding` | Unfolds constant expressions (x86_64, partial ARM64) |
| **Validation** | `symbolic` | Bounded symbolic step via angr, ELF x86_64 only, advisory |
| **Validation** | `cfg-integrity` | Reachability and edge preservation checks |
| **Formats** | PE | Handler via LIEF, minimal transformation support |
| **Formats** | Mach-O | Handler via LIEF, load command parsing, partial Fat binary support |
| **Architecture** | ARM64 | NOP insertion (`mov xzr, xzr`), register maps defined |

### Planned / Stub

These modules have framework code but do not yet apply real binary mutations:

| Area | Status |
|------|--------|
| Control Flow Flattening (`cff`) | Analyzes CFG structure, does not flatten |
| Opaque Predicates (`opaque`) | Analyzes candidates, no insertion |
| Code Virtualization | Opcode definitions exist, no VM generation |
| Code Mobility | Framework only |
| Function Outlining | Framework only |
| API Hashing | Windows-specific, stub |
| Import Obfuscation | Framework only |
| Self-Modifying Code | Encryption schemes defined, no application |
| Anti-Disassembly | Technique dataclasses only |
| ARM32 mutations | Register maps exist, untested |

## Architecture Support Detail

| Architecture | NOP | Substitute | Register | Expand | Block | Dead Code |
|--------------|-----|-----------|----------|--------|-------|-----------|
| **x86_64** | Yes | Yes | Yes | Yes | Yes | Yes |
| **x86** | Yes | Yes | Yes | Partial | Partial | Partial |
| **ARM64** | Partial | No | Partial | No | No | No |
| **ARM32** | No | No | No | No | No | No |

### Instruction Equivalence Rules

- **x86/x86_64**: 100+ rules in `r2morph/mutations/equivalences/x86_rules.yaml` - bidirectional groups covering zero registers, self-moves, flag-preserving patterns, XOR/SUB equivalence
- **ARM64**: Register classes defined in `arm64_rules.yaml`, no instruction groups yet
- **ARM32**: Register classes defined in `arm_rules.yaml`, no instruction groups yet

## Quick Start

```bash
# Stable mutate + validate flow
r2morph mutate input_binary -o output_binary

# Explicit mutations with JSON report
r2morph mutate input_binary -o output_binary -m nop -m substitute --report report.json

# SARIF 2.1.0 report for CI/CD (GitHub Security, Azure DevOps, SonarQube)
r2morph mutate input_binary -o output_binary --report report.sarif --format sarif

# Reproducible stable mutation run
r2morph mutate input_binary -o output_binary --seed 1337

# Runtime validation of an original/mutated pair
r2morph validate input_binary output_binary

# Runtime validation with a reusable corpus
r2morph validate input_binary output_binary --corpus dataset/runtime_corpus.json
```

---

## Usage

### Command Line Interface

```bash
# Stable tracked mutation flow
r2morph mutate input_binary -o output_binary -m nop -m substitute -m register

# Reproducible mutation selection
r2morph mutate input_binary -o output_binary --seed 1337

# SARIF output directly from mutate
r2morph mutate input_binary -o output_binary --format sarif --report mutations.sarif

# Experimental symbolic precheck mode (ELF x86_64 only)
r2morph mutate input_binary -o output_binary --validation-mode symbolic

# Allow a limited symbolic pass explicitly
r2morph mutate input_binary -o output_binary --validation-mode symbolic \
  --allow-limited-symbolic -m register

# Degrade a limited symbolic pass to runtime validation instead of blocking
r2morph mutate input_binary -o output_binary --validation-mode symbolic \
  --limited-symbolic-policy degrade-runtime -m register

# Export a machine-readable report
r2morph mutate input_binary -o output_binary --report report.json

# Fail the CLI run unless the final report reaches a minimum symbolic severity
r2morph mutate input_binary -o output_binary --report report.json \
  --min-severity bounded-only

# Fail unless a specific pass reaches the required local severity
r2morph mutate input_binary -o output_binary --report report.json \
  --require-pass-severity InstructionSubstitution=bounded-only

# Short mutation aliases also work in pass severity gating
r2morph mutate input_binary -o output_binary --report report.json \
  --require-pass-severity nop=not-requested

# Validate a mutated binary against the original
r2morph validate input_binary output_binary

# Validate with a JSON corpus of runtime cases
r2morph validate input_binary output_binary --corpus dataset/runtime_corpus.json

# Ignore trailing whitespace differences in stdout/stderr
r2morph validate input_binary output_binary --corpus dataset/runtime_corpus.json --normalize-whitespace

# Run mutate with runtime validation backed by a real corpus
r2morph mutate input_binary -o output_binary \
  --validation-mode runtime \
  --runtime-corpus dataset/runtime_corpus.json

# Display a saved report
r2morph report report.json

# Display as SARIF
r2morph report report.json --format sarif

# Use the saved report as a CI gate
r2morph report report.json --require-results --min-severity mismatch

# Triage only runs where persisted CLI gates failed
r2morph report report.json --only-failed-gates --summary-only

# Restrict the report to one pass
r2morph report report.json --only-pass nop

# Triage only symbolic observable mismatches
r2morph report report.json --only-mismatches

# Export a filtered report JSON for CI
r2morph report report.json --only-pass InstructionSubstitution --output filtered-report.json
```

#### Report Filter Quick Reference

| Filter | Purpose | Example |
| --- | --- | --- |
| `--format <json\|sarif>` | Output format (JSON default, SARIF 2.1.0) | `r2morph report report.json --format sarif` |
| `--only-pass <pass-or-alias>` | Restrict to one pass | `r2morph report report.json --only-pass nop` |
| `--only-status <symbolic_status>` | Restrict by symbolic status | `r2morph report report.json --only-status bounded-step-observable-mismatch` |
| `--only-mismatches` | Show only symbolic observable mismatches | `r2morph report report.json --only-mismatches` |
| `--only-degraded` | Show only degraded validation modes | `r2morph report report.json --only-degraded --summary-only` |
| `--only-failed-gates` | Show only failed severity gates | `r2morph report report.json --only-failed-gates --summary-only` |
| `--only-expected-severity <sev>` | Filter gate failures by severity | `r2morph report report.json --only-failed-gates --only-expected-severity clean` |
| `--only-pass-failure <pass>` | Filter gate failures by pass | `r2morph report report.json --only-failed-gates --only-pass-failure nop` |
| `--summary-only` | Print textual triage summary only | `r2morph report report.json --summary-only` |
| `--output <file>` | Export filtered JSON | `r2morph report report.json --only-pass nop --output filtered.json` |
| `--require-results` | Exit `1` when filtered view is empty | `r2morph report report.json --only-pass nop --require-results` |
| `--min-severity <severity>` | Require minimum severity in view | `r2morph report report.json --require-results --min-severity mismatch` |

Alias notes:
- Stable aliases accepted: `nop`, `substitute`, `register`.
- The textual summary shows alias resolution: `nop -> NopInsertion`.

### SARIF 2.1.0 Integration

Reports in SARIF format include:

- **MITRE ATT&CK taxonomy** mapping mutations to techniques (T1027 Obfuscated Files, T1027.001 Binary Padding, T1027.002 Software Packing)
- **Partial fingerprints** (SHA256) for deduplication across CI runs
- **Code flows** showing mutation chains per function
- **Related locations** linking mutations to their validation failures
- **Disassembly snippets** in the rendered field alongside hex bytes
- **Fix suggestions** with byte-level replacements

Compatible with GitHub Code Scanning, Azure DevOps, SonarQube, and any SARIF 2.1.0 consumer.

### Python Library

```python
from r2morph import MorphEngine
from r2morph.mutations import NopInsertionPass, InstructionSubstitutionPass, RegisterSubstitutionPass

with MorphEngine() as engine:
    engine.load_binary("input.elf").analyze()

    engine.add_mutation(NopInsertionPass())
    engine.add_mutation(InstructionSubstitutionPass())
    engine.add_mutation(RegisterSubstitutionPass())

    result = engine.run(validation_mode="structural", report_path="mutation_report.json")
    engine.save("output.elf")

print(f"Applied {result['total_mutations']} mutations")
```

### Runtime Corpus

`r2morph validate --corpus` accepts a JSON array of runtime test cases. A reusable example lives at `dataset/runtime_corpus.json`.
For side effects, `dataset/runtime_corpus_files.json` shows the `monitored_files` form used with `--compare-files`.

```json
[
  {
    "description": "default-exec",
    "args": [],
    "stdin": "",
    "expected_exitcode": 0
  },
  {
    "description": "help-output",
    "args": ["--help"],
    "stdin": "",
    "expected_exitcode": 0
  }
]
```

Example with file side effects:

```bash
r2morph validate original mutated \
  --corpus dataset/runtime_corpus_files.json \
  --compare-files
```

Runtime validation can also normalize trailing whitespace differences:

```bash
r2morph validate original mutated \
  --corpus dataset/runtime_corpus.json \
  --normalize-whitespace
```

### Detection & Analysis

r2morph includes a detection suite for analyzing obfuscated binaries:

| Module | Capability |
|--------|-----------|
| **Obfuscation Detector** | Commercial packer signatures (VMProtect, Themida, UPX, etc.), confidence scoring |
| **Entropy Analyzer** | Section entropy analysis for packing/encryption detection |
| **Pattern Matcher** | Anti-debug, anti-VM, string encryption, import hiding detection |
| **Similarity Hasher** | Fuzzy hashing for binary comparison (ssdeep-style) |
| **Control Flow Detector** | CFF, opaque predicates, VM dispatch, MBA expression detection |
| **Packer Signatures** | 50+ signature database with categorized detection |

### Devirtualization (Experimental)

```python
from r2morph import Binary
from r2morph.detection import ObfuscationDetector
from r2morph.devirtualization import VMHandlerAnalyzer, MBASolver

with Binary("vmprotected.exe") as binary:
    binary.analyze()

    detector = ObfuscationDetector()
    result = detector.analyze_binary(binary)

    if result.vm_detected:
        vm_analyzer = VMHandlerAnalyzer(binary)
        handlers = vm_analyzer.analyze_vm_architecture()

        # Z3-based MBA simplification
        mba_solver = MBASolver()
        simplified = mba_solver.simplify_handlers(handlers)
```

| Module | Status | Notes |
|--------|--------|-------|
| **VM Handler Analyzer** | Partial | Pattern-based handler classification |
| **MBA Solver** | Working | Z3 SMT solver, max 8 variables, timeout-bounded |
| **CFO Simplifier** | Framework | Pattern library defined, application incomplete |
| **Binary Rewriter** | Framework | Patch/relocation infrastructure |

### Instrumentation (Experimental)

Optional Frida integration for dynamic analysis:

```python
from r2morph.instrumentation import FridaEngine

frida = FridaEngine()
result = frida.instrument_binary("target.exe")
```

Supports process spawning, script injection, API call logging, and anti-analysis detection. Requires `frida` package.

## Experimental Symbolic Validation

`--validation-mode symbolic` is available as an experimental mode for bounded prechecks on the stable core. It is intentionally narrow:

- `ELF x86_64` only
- Stable passes only (`nop`, `substitute`, `register`)
- Small mutated regions only
- Structural validation remains the blocking fallback
- Uses angr for bounded symbolic execution (advisory, not proof)

Reports identify whether symbolic coverage was supported, whether the backend initialized, whether a bounded symbolic step ran for the mutated regions, and why the run fell back or remained unproven.
Each report also exposes `pass_support.<PassName>.validator_capabilities`, so consumers can distinguish between passes with stronger symbolic evidence such as `InstructionSubstitution` and passes where `runtime` remains the recommended release gate, such as `RegisterSubstitution`.

---

## Supported Transformations

### Stable Mutations (x86_64 ELF, tested)

| Pass | Description |
|------|-------------|
| **NOP Insertion** | Inserts benign NOP instructions at safe locations within functions |
| **Instruction Substitution** | Replaces instructions with semantically equivalent alternatives from bidirectional equivalence groups |
| **Register Substitution** | Substitutes registers while preserving program semantics via liveness analysis |

### Experimental Mutations (working, limited testing)

| Pass | Description |
|------|-------------|
| **Block Reordering** | Reorders basic blocks with jump patching to preserve control flow |
| **Instruction Expansion** | Expands single instructions into longer equivalent sequences (flag-safe subset) |
| **Dead Code Injection** | Injects semantically neutral code in padding regions |
| **Short Jump Patching** | Replaces short jumps with equivalent instruction sequences |
| **Constant Unfolding** | Unfolds constant expressions into multi-instruction equivalents |

### Planned (framework exists, not yet functional)

Control Flow Flattening, Opaque Predicates, Code Virtualization, Code Mobility, Function Outlining, API Hashing, Import Obfuscation, Self-Modifying Code, Anti-Disassembly, Data Flow Mutation

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

## Examples

### Basic Binary Analysis

```python
from r2morph import Binary

with Binary("/path/to/binary") as binary:
    binary.analyze()

    functions = binary.get_functions()
    print(f"Found {len(functions)} functions")

    arch = binary.get_arch_info()
    print(f"Architecture: {arch['arch']} ({arch['bits']}-bit)")
```

---

## Requirements

- Python 3.10+
- radare2
- See `pyproject.toml` for full dependency list
- Optional: `lief` (PE/Mach-O support), `angr` (symbolic validation), `frida` (instrumentation), `z3-solver` (MBA simplification)
- For local development: `requirements-dev.txt`

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
