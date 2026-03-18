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
| **Tracked Mutations** | Every applied mutation can be recorded with addresses, bytes, and disassembly |
| **Validation Pipeline** | Structural validation in the engine, optional runtime validation, rollback on failure |
| **Machine-Readable Reports** | Export JSON reports for CI, regression checks, and auditability |
| **CLI + Python API** | Run as `mutate`, `validate`, `report`, or embed as a library |
| **radare2-backed Analysis** | Reuse radare2/r2pipe for disassembly and binary metadata |
| **Experimental Modules** | Devirtualization, enhanced analysis, instrumentation, and anti-analysis helpers remain secondary/experimental |

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

| Area | Supported | Stability |
|------|-----------|-----------|
| Formats | ELF | Stable |
| Architectures | x86_64 | Stable |
| Mutations | `nop`, `substitute`, `register` | Stable |
| Validators | `structural`, `runtime` | Stable / Supported |
| Output | JSON report + mutated binary | Stable |

### Experimental / Secondary

| Area | Supported | Stability |
|------|-----------|-----------|
| Formats | PE, Mach-O | Experimental |
| Mutations | `expand`, `block`, `opaque`, `dead-code`, `cff` | Experimental |
| Validation | symbolic equivalence | Experimental |
| Analysis | devirtualization, Frida, anti-analysis, packer analysis | Experimental |

## Quick Start

```bash
# Stable mutate + validate flow
r2morph input_binary output_binary

# Explicit mutate command with report
r2morph mutate input_binary -o output_binary --report mutation_report.json

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
# Stable default flow
r2morph input_binary output_binary

# Stable tracked mutation flow
r2morph mutate input_binary -o output_binary -m nop -m substitute -m register

# Reproducible mutation selection
r2morph mutate input_binary -o output_binary --seed 1337

# Experimental symbolic precheck mode
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

# The generated report preserves gate requests and outcomes in `gate_evaluation`

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

# Display a saved report with symbolic coverage summaries and mismatch triage when available
r2morph report report.json

# Use the saved report as a CI gate
r2morph report report.json --require-results --min-severity mismatch

# Triage only runs where persisted CLI gates failed
r2morph report report.json --only-failed-gates --summary-only
# The summary includes compact gate failure causes for fast triage

# Restrict persisted gate failures to one expected severity
r2morph report report.json --only-failed-gates --only-expected-severity clean --summary-only

# Restrict persisted gate failures to one pass
r2morph report report.json --only-failed-gates --only-pass-failure NopInsertion --summary-only

# Stable mutation aliases work for gate triage too
r2morph report report.json --only-failed-gates --only-pass-failure nop --summary-only

# Triage only symbolic observable mismatches
r2morph report report.json --only-mismatches

# Restrict the report to one pass, optionally combined with mismatch triage
r2morph report report.json --only-pass InstructionSubstitution --only-mismatches

# Stable mutation aliases also work in pass filtering
r2morph report report.json --only-pass nop

# Filter directly by symbolic status
r2morph report report.json --only-status bounded-step-observable-mismatch

# Show only reports where the effective validation mode was degraded
r2morph report report.json --only-degraded
# The report summary includes the degraded pass set and symbolic confidence for each cause

# Show only the textual summary for terminal triage
r2morph report report.json --summary-only

# Export a filtered report JSON for CI or post-processing
r2morph report report.json --only-pass InstructionSubstitution --output filtered-report.json

# Fail in CI when a filtered view has no matching mutations
r2morph report report.json --only-pass InstructionSubstitution --require-results

# Fail in CI when a filtered gate view has no matching failures
r2morph report report.json --only-failed-gates --only-expected-severity clean --require-results
r2morph report report.json --only-failed-gates --only-pass-failure nop --require-results

# The exported JSON includes `filtered_summary` for the active view
r2morph report report.json --only-status bounded-step-passed --output filtered-report.json

# `filtered_summary.symbolic_statuses` exposes the status distribution for the current view
r2morph report report.json --only-pass InstructionSubstitution --output filtered-report.json

# Gate-focused filtered views also preserve `gate_failures`, `gate_failure_priority`,
# `gate_failure_severity_priority`, and normalized `report_filters`
r2morph report report.json --only-failed-gates --only-pass-failure nop --output filtered-report.json
```

#### Report Filter Quick Reference

| Filter | Purpose | Example |
| --- | --- | --- |
| `--only-pass <pass-or-alias>` | Restrict mutations to one pass in the current view | `r2morph report report.json --only-pass nop` |
| `--only-status <symbolic_status>` | Restrict mutations to one symbolic status | `r2morph report report.json --only-status bounded-step-observable-mismatch` |
| `--only-mismatches` | Show only symbolic observable mismatches | `r2morph report report.json --only-mismatches` |
| `--only-degraded` | Show only runs where requested and effective validation modes differ | `r2morph report report.json --only-degraded --summary-only` |
| `--only-failed-gates` | Show only runs where persisted CLI gates failed | `r2morph report report.json --only-failed-gates --summary-only` |
| `--only-expected-severity <severity>` | Restrict persisted gate failures by expected severity | `r2morph report report.json --only-failed-gates --only-expected-severity clean` |
| `--only-pass-failure <pass-or-alias>` | Restrict persisted gate failures to one pass | `r2morph report report.json --only-failed-gates --only-pass-failure nop` |
| `--summary-only` | Print only the textual triage summary | `r2morph report report.json --summary-only` |
| `--output <file>` | Export the filtered JSON view for CI/post-processing | `r2morph report report.json --only-pass nop --output filtered.json` |
| `--require-results` | Exit `1` when the filtered view is empty | `r2morph report report.json --only-failed-gates --only-pass-failure nop --require-results` |
| `--min-severity <severity>` | Require at least one pass in the view at or above the given severity | `r2morph report report.json --require-results --min-severity mismatch` |

Alias notes:
- Stable aliases are accepted in `--only-pass` and `--only-pass-failure`: `nop`, `substitute`, `register`.
- The textual summary shows alias resolution explicitly, for example `nop -> NopInsertion`.

### Python Library

```python
from r2morph import MorphEngine
from r2morph.mutations import NopInsertionPass, InstructionSubstitutionPass

with MorphEngine() as engine:
    engine.load_binary("input.exe").analyze()

    engine.add_mutation(NopInsertionPass())
    engine.add_mutation(InstructionSubstitutionPass())
    engine.add_mutation(RegisterSubstitutionPass())

    result = engine.run(validation_mode="structural", report_path="mutation_report.json")
    engine.save("output.exe")

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

### Experimental Advanced Analysis

```python
from r2morph import Binary
from r2morph.detection import ObfuscationDetector
from r2morph.analysis.symbolic import AngrBridge, PathExplorer
from r2morph.instrumentation import FridaEngine
from r2morph.devirtualization import VMHandlerAnalyzer, MBASolver

with Binary("vmprotected.exe") as binary:
    binary.analyze()

    detector = ObfuscationDetector()
    result = detector.analyze_binary(binary)

    if result.vm_detected:
        angr_bridge = AngrBridge(binary)
        explorer = PathExplorer(angr_bridge)
        vm_result = explorer.explore_vm_handlers()

        frida_engine = FridaEngine()
        runtime_result = frida_engine.instrument_binary("vmprotected.exe")

        vm_analyzer = VMHandlerAnalyzer(binary)
        handlers = vm_analyzer.analyze_vm_architecture()

        mba_solver = MBASolver()
        simplified = mba_solver.simplify_handlers(handlers)
```

This advanced analysis workflow remains experimental and is secondary to the mutation engine.
See `docs/enhanced_analysis.md` for more details.
CLI access lives under the secondary namespace:

```bash
r2morph experimental analyze-enhanced sample.bin --detect-only
```

## Experimental Symbolic Validation

`--validation-mode symbolic` is available as an experimental mode for bounded prechecks on the stable core. It is intentionally narrow:

- `ELF x86_64` only
- Stable passes only
- Small mutated regions only
- Structural validation remains the blocking fallback

Reports identify whether symbolic coverage was supported, whether the backend initialized, whether a bounded symbolic step ran for the mutated regions, and why the run fell back or remained unproven.
Each report also exposes `pass_support.<PassName>.validator_capabilities`, so consumers can distinguish between passes with stronger symbolic evidence such as `InstructionSubstitution` and passes where `runtime` remains the recommended release gate, such as `RegisterSubstitution`.

For `InstructionSubstitution`, the experimental report also flags when a mutated region comes from a known equivalence group and, when possible, compares a small set of observable register/flag effects on both snippets and bounded states from the real pre-pass/post-pass binaries. This remains a scoped hint, not a general semantic proof.

---

## Supported Transformations

**Stable Mutations**
- Instruction Substitution
- NOP Insertion
- Register Reassignment

**Experimental Mutations**
- Block Reordering
- Instruction Expansion
- Opaque Predicates
- Dead Code Injection
- Control Flow Flattening

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
