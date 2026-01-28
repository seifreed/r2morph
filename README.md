<p align="center">
  <img src="https://img.shields.io/badge/r2morph-Binary%20Transformation-blue?style=for-the-badge" alt="r2morph">
</p>

<h1 align="center">r2morph</h1>

<p align="center">
  <strong>Metamorphic binary transformation engine for analysis, mutation, and validation</strong>
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

**r2morph** is a framework for analyzing and transforming binary executables through semantic‑preserving mutations. It leverages **radare2** and **r2pipe** to perform deep binary analysis, apply metamorphic transformations, and validate results across PE/ELF/Mach‑O targets.

### Key Features

| Feature | Description |
|---------|-------------|
| **Deep Binary Analysis** | radare2‑backed analysis and disassembly | 
| **Metamorphic Mutations** | Instruction substitution, NOP insertion, block reordering, opaque predicates, dead code | 
| **Multi‑Format** | PE, ELF, Mach‑O support | 
| **CLI + Python API** | Use via command line or library integration | 
| **Validation & Regression** | Built‑in benchmark, regression, and fuzzing utilities | 
| **Relocations & Code Caves** | Code cave discovery and reference updates | 
| **Enhanced Analysis (Optional)** | Angr symbolic execution, Frida instrumentation, Syntia integration | 
| **macOS/Windows Code Signing** | Format‑specific helpers and signing workflows | 

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

## Quick Start

```bash
# Basic transform
r2morph input_binary output_binary

# Chain mutations
r2morph input.exe output.exe -m nop -m substitute -v

# Aggressive mutation
r2morph -i input.exe -o output.exe --aggressive
```

---

## Usage

### Command Line Interface

```bash
# Analyze and mutate
r2morph input_binary output_binary

# Specify mutations
r2morph input.exe output.exe -m nop -m substitute

# Verbose output
r2morph input.exe output.exe -v
```

### Python Library

```python
from r2morph import MorphEngine
from r2morph.mutations import NopInsertionPass, InstructionSubstitutionPass

with MorphEngine() as engine:
    engine.load_binary("input.exe").analyze()

    engine.add_mutation(NopInsertionPass())
    engine.add_mutation(InstructionSubstitutionPass())

    result = engine.run()
    engine.save("output.exe")

print(f"Applied {result['total_mutations']} mutations")
```

### Enhanced Obfuscated Binary Analysis (Optional)

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

See `docs/enhanced_analysis.md` for more details.

---

## Supported Transformations

**Basic Mutations**
- Instruction Substitution
- NOP Insertion
- Register Reassignment
- Block Reordering
- Instruction Expansion

**Advanced Mutations**
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
