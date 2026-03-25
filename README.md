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

**r2morph** is a metamorphic mutation engine that applies tracked binary transformations with validation, rollback, and machine-readable reports. It uses **radare2** for analysis and supports 18 mutation passes across 4 architectures.

### Key Features

| Feature | Description |
|---------|-------------|
| **18 Mutation Passes** | From stable NOP/substitute/register to experimental CFF, virtualization, and self-modifying code |
| **4 Architectures** | x86_64, x86, ARM64, ARM32 |
| **3 Binary Formats** | ELF (stable), PE and Mach-O (experimental, via LIEF) |
| **4 Validation Modes** | Structural, runtime, symbolic (angr), CFG integrity |
| **Session Management** | Checkpoint/rollback system preserving binary state across mutation passes |
| **SARIF 2.1.0 Reports** | OASIS SARIF with MITRE ATT&CK taxonomy, fingerprints, code flows |
| **JSON Reports** | Documented schema, metadata, timing, gate evaluation |
| **Detection Suite** | Packer signatures, entropy analysis, pattern matching, similarity hashing |
| **Devirtualization** | VM handler analysis, MBA simplification (Z3-based) |

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
pip install r2morph                  # Basic
pip install "r2morph[enhanced]"      # + angr, lief, z3
pip install "r2morph[all]"           # + frida, hypothesis
```

### Development Install

```bash
git clone https://github.com/seifreed/r2morph.git
cd r2morph
pip install -e ".[dev]"
```

---

## Support Matrix

### Formats

| Format | Status | Section Creation | Notes |
|--------|--------|-----------------|-------|
| **ELF** | Stable | Via LIEF | Full section handling, relocations, code caves |
| **PE** | Experimental | Via LIEF | Section creation, checksum fixing |
| **Mach-O** | Experimental | Via LIEF | Load command parsing, Fat binary support |

### Architectures

| Architecture | NOP | Substitute | Register | Expand | Block | Dead Code |
|--------------|-----|-----------|----------|--------|-------|-----------|
| **x86_64** | Yes | Yes | Yes | Yes | Yes | Yes |
| **x86** | Yes | Yes | Yes | Yes | Yes | Yes |
| **ARM64** | Yes | Yes | Yes | Yes | Yes | Yes |
| **ARM32** | Yes | Yes | Yes | Yes | Yes | Yes |

### Instruction Equivalence Rules

- **x86/x86_64**: 100+ rules in `x86_rules.yaml` - bidirectional groups covering zero registers, self-moves, flag-preserving patterns, XOR/SUB equivalence
- **ARM32**: 10+ groups in `arm_rules.yaml` - zero, increment, decrement, self-move, shift, negate, double, compare for r0-r11
- **ARM64**: Register classes defined in `arm64_rules.yaml`

---

## Mutation Passes

### Stable (tested, production-ready)

| Pass | CLI Flag | Description |
|------|----------|-------------|
| **NOP Insertion** | `-m nop` | Inserts benign NOP equivalents at safe locations |
| **Instruction Substitution** | `-m substitute` | Replaces instructions with semantically equivalent alternatives |
| **Register Substitution** | `-m register` | Substitutes registers via liveness analysis |

### Experimental (working, limited testing)

| Pass | CLI Flag | Description |
|------|----------|-------------|
| **Instruction Expansion** | `-m expand` | Expands single instructions into longer equivalent sequences |
| **Block Reordering** | `-m block` | Reorders basic blocks with jump patching |
| **Dead Code Injection** | `-m dead-code` | Injects semantically neutral code in padding regions |
| **Control Flow Flattening** | `-m cff` | Inserts opaque predicates and jump obfuscation |
| **Opaque Predicates** | `-m opaque` | Writes opaque predicate instructions into basic blocks |
| **Code Virtualization** | `-m code-virtualization` | Translates instructions to VM bytecode with dispatcher |
| **Anti-Disassembly** | `-m anti-disassembly` | Injects anti-disassembly snippets |
| **Data Flow Mutation** | `-m data-flow` | Data flow analysis-driven safe substitutions |
| **Short Jump Patching** | `-m short-jump` | Patches short jumps to equivalent sequences |
| **Constant Unfolding** | `-m constant-unfolding` | Unfolds constant expressions into multi-instruction equivalents |
| **Code Mobility** | `-m code-mobility` | Relocates blocks to code caves with trampolines |
| **Function Outlining** | `-m function-outlining` | Distributes function chunks across code caves |
| **API Hashing** | `-m api-hashing` | Hash trampolines obscuring PLT references |
| **Import Obfuscation** | `-m import-obfuscation` | Jump stub indirection for import calls |
| **Self-Modifying Code** | `-m self-modifying` | XOR-encrypts function bodies with runtime decryptor |

---

## Validation

| Mode | Flag | Status | Description |
|------|------|--------|-------------|
| **Structural** | `--validation-mode structural` | Stable | Binary format integrity checks (always runs) |
| **Runtime** | `--validation-mode runtime` | Stable | Compares original vs mutated execution (exit code, stdout, stderr, files) |
| **Symbolic** | `--validation-mode symbolic` | Experimental | Bounded symbolic step via angr (ELF x86_64, advisory) |
| **CFG Integrity** | Automatic | Experimental | Reachability and edge preservation checks |

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
r2morph validate original.elf mutated.elf --corpus dataset/runtime_corpus.json

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
