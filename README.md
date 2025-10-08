# r2morph

A metamorphic binary transformation engine based on r2pipe and radare2.

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![codecov](https://codecov.io/gh/seifreed/r2morph/branch/main/graph/badge.svg)](https://codecov.io/gh/seifreed/r2morph)
[![CI](https://github.com/seifreed/r2morph/workflows/Python%20Package/badge.svg)](https://github.com/seifreed/r2morph/actions)
[![GitHub issues](https://img.shields.io/github/issues/seifreed/r2morph)](https://github.com/seifreed/r2morph/issues)
[![GitHub stars](https://img.shields.io/github/stars/seifreed/r2morph)](https://github.com/seifreed/r2morph/stargazers)

**Author**: Marc Rivero | [@seifreed](https://github.com/seifreed)
**Contact**: mriverolopez@gmail.com

---

## Overview

**r2morph** is a powerful framework for analyzing and transforming binary executables through semantic-preserving mutations. It leverages radare2 and r2pipe to perform deep binary analysis and apply metamorphic transformations that change the binary signature while maintaining program semantics.

**Perfect for**:
- Security research and malware analysis
- Evasion technique testing
- Binary obfuscation research
- Defensive security tool development

---

## Key Features

- **Deep Binary Analysis**: Leverage radare2's powerful analysis engine
- **Metamorphic Transformations**: Apply semantic-preserving code mutations
- **Modular Architecture**: Extensible pipeline-based design
- **Multi-Architecture**: Support for PE/ELF/Mach-O on x86/x64/ARM
- **Plugin System**: Easy-to-create custom mutation passes
- **Rich Analytics**: Detailed statistics and reporting
- **CLI + Python API**: Powerful command-line and programmatic interfaces
- **Validation & Testing**: Automated validation, fuzzing, regression tests
- **Relocation Management**: Code cave finding, reference updates
- **Anti-Detection Analysis**: Evasion scoring, entropy analysis, similarity hashing
- **ARM64/ARM32 Support**: 180+ patterns for ARM architectures
- **Advanced Mutations**: Opaque predicates, dead code, control flow flattening
- **Platform Support**: Code signing for macOS/Windows, format-specific handlers
- **Profile-Guided**: Hot path detection, execution profiling
- **Session Management**: Checkpoints, rollback, versioning
- **Memory-Efficient Mode**: Automatic OOM prevention for large binaries (>50MB)

---

## Quick Start

### Installation

#### Prerequisites

- Python 3.10 or higher
- radare2 installed on your system

#### Install radare2

```bash
git clone https://github.com/radareorg/radare2
cd radare2
sys/install.sh
```

#### Install r2morph

```bash
pip install r2morph

git clone https://github.com/seifreed/r2morph.git
cd r2morph
pip install -e .

pip install -e ".[dev]"
```

### Basic Usage

```bash
r2morph input_binary output_binary

r2morph input.exe output.exe -m nop -m substitute -v

r2morph -i input.exe -o output.exe --aggressive
```

### Python API

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

---

## Supported Transformations

### Basic Mutations
- **Instruction Substitution**: Replace instructions with semantic equivalents (90+ patterns)
- **NOP Insertion**: Insert dead code at safe locations
- **Register Reassignment**: Swap equivalent registers
- **Block Reordering**: Rearrange code blocks (preserving control flow)
- **Instruction Expansion**: Expand simple instructions into complex equivalents

### Advanced Mutations ⚡
- **Opaque Predicates**: Inject always-true/false conditionals
- **Dead Code Injection**: Insert code that never executes (3 complexity levels)
- **Control Flow Flattening**: Transform CFG into dispatcher pattern

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

### Validation & Testing

```python
from r2morph.validation import BinaryValidator, MutationFuzzer

validator = BinaryValidator()
result = validator.validate(original, mutated)

fuzzer = MutationFuzzer(num_tests=100)
fuzz_result = fuzzer.fuzz(original, mutated)
```

### Evasion Analysis

```python
from r2morph.detection import EvasionScorer

scorer = EvasionScorer()
score = scorer.score(original, mutated)
print(score)
```

### Session Management

```python
from r2morph import MorphSession

session = MorphSession()
session.start(original)

session.checkpoint("stage1")
session.apply_mutation(NopPass())

session.rollback_to("stage1")

session.finalize(output)
```

### Custom Mutation Pass

```python
from r2morph.mutations.base import MutationPass
from r2morph.core.binary import Binary

class MyCustomMutation(MutationPass):
    def __init__(self):
        super().__init__(name="MyCustomMutation")

    def apply(self, binary: Binary):
        mutations_applied = 0

        functions = binary.get_functions()
        for func in functions:
            pass

        return {
            "mutations_applied": mutations_applied,
            "custom_metric": 42,
        }

engine.add_mutation(MyCustomMutation())
```

See the `examples/` directory for complete examples:
- `basic_analysis.py`: Simple binary analysis
- `morph_binary.py`: Apply transformations to a binary
- `advanced_analysis.py`: Advanced analysis features
- `advanced_mutations.py`: Using advanced mutations

---

## Memory-Efficient Mode

r2morph automatically detects large binaries and enables memory-efficient mode to prevent OOM crashes:

### Automatic Detection
- **Triggers**: Binaries >50MB or >3000 functions
- **Batch Processing**: r2 restarts every 1000 mutations to free memory
- **Conservative Limits**: Reduced mutations per function (2 instead of 5)
- **Low-Memory r2 Config**: Disables caching (`bin.cache=false`, `io.cache=false`)

### Example
```bash
# Automatically handles large binaries (e.g., Qt6WebEngineCore.dll - 148MB)
r2morph large_binary.dll morphed.dll

# Output:
# Large binary detected (147.3 MB, 4261 functions)
# Enabling memory-efficient mode to prevent OOM crashes
# Batch checkpoint: 1000 mutations applied. Reloading r2 to free memory...
```

### Pipeline Integration
Memory-efficient mode is **100% transparent** - no code changes needed. Just run r2morph normally and it will auto-detect and protect against OOM.

---

## Architecture

```
┌─────────────┐
│   Binary    │  ← Load binary with r2pipe
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Analysis   │  ← Analyze with radare2
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Pipeline   │  ← Execute mutation passes
│             │
│  ┌────────┐ │
│  │ Pass 1 │ │
│  └────────┘ │
│  ┌────────┐ │
│  │ Pass 2 │ │
│  └────────┘ │
│  ┌────────┐ │
│  │ Pass N │ │
│  └────────┘ │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Output    │  ← Save morphed binary
└─────────────┘
```

### Module Structure

```
r2morph/
├── core/           # Binary abstraction, engine
│   ├── binary.py       # Binary abstraction
│   ├── engine.py       # Morphing engine
│   ├── function.py     # Function representation
│   └── instruction.py  # Instruction representation
├── mutations/      # 8 mutation passes + ARM rules
│   ├── base.py                     # Base mutation class
│   ├── nop_insertion.py            # NOP insertion
│   ├── instruction_substitution.py # Instruction substitution
│   ├── register_substitution.py    # Register reassignment
│   ├── block_reordering.py         # Block reordering
│   ├── instruction_expansion.py    # Instruction expansion
│   ├── opaque_predicates.py        # Opaque predicates
│   ├── dead_code_injection.py      # Dead code injection
│   ├── control_flow_flattening.py  # CFG flattening
│   ├── arm_rules.py                # ARM equivalence patterns
│   └── arm_expansion_rules.py      # ARM expansion patterns
├── analysis/       # CFG, dependencies, diff analysis
│   ├── analyzer.py      # Binary analyzer
│   ├── cfg.py           # Control flow graph
│   ├── dependencies.py  # Data dependencies
│   ├── invariants.py    # Code invariants
│   └── diff_analyzer.py # Binary diff analysis
├── validation/     # Testing, fuzzing, regression
│   ├── validator.py     # Binary validator
│   ├── fuzzer.py        # Mutation fuzzer
│   └── regression.py    # Regression tester
├── relocations/    # Code caves, reference updates
│   ├── manager.py           # Relocation manager
│   ├── cave_finder.py       # Code cave finder
│   └── reference_updater.py # Reference updater
├── detection/      # Evasion scoring, entropy
│   ├── evasion_scorer.py    # Evasion scorer
│   ├── similarity_hasher.py # Fuzzy hashing
│   └── entropy_analyzer.py  # Entropy analysis
├── platform/       # PE/ELF/Mach-O handlers, code signing
│   ├── codesign.py      # Code signing
│   ├── pe_handler.py    # PE format handler
│   ├── elf_handler.py   # ELF format handler
│   └── macho_handler.py # Mach-O format handler
├── profiling/      # Hot path detection, profiling
│   ├── profiler.py          # Execution profiler
│   └── hotpath_detector.py  # Hot path detector
├── pipeline/       # Pipeline orchestration
│   └── pipeline.py      # Pipeline management
├── utils/          # Utilities
│   ├── logging.py       # Logging configuration
│   └── assembler.py     # Assembly helpers
├── session.py      # Checkpoint & rollback
└── cli.py          # Command-line interface
```

---

## Contributing

### Creating a New Mutation Pass

1. Create a new file in `r2morph/mutations/`
2. Subclass `MutationPass`
3. Implement the `apply()` method
4. Add to `r2morph/mutations/__init__.py`

Example:

```python
from r2morph.mutations.base import MutationPass

class MyMutation(MutationPass):
    def __init__(self, config=None):
        super().__init__(name="MyMutation", config=config)

    def apply(self, binary):
        return {"mutations_applied": 0}
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

**This tool is for research and educational purposes only.** Users are responsible for ensuring they have proper authorization before analyzing or modifying any binary. The authors are not responsible for any misuse of this tool.

---

## Acknowledgments

- Built on top of [radare2](https://github.com/radareorg/radare2)
- Uses [r2pipe](https://github.com/radareorg/radare2-r2pipe) for radare2 integration
- Inspired by metamorphic engine research

---

## Contact & Support

- **Author**: Marc Rivero | [@seifreed](https://github.com/seifreed)
- **Email**: mriverolopez@gmail.com
- **Issues**: [GitHub Issues](https://github.com/seifreed/r2morph/issues)
- **Repository**: https://github.com/seifreed/r2morph

---

## 📖 Citation

If you use r2morph in your research, please cite:

```bibtex
@software{r2morph,
  title = {r2morph: A Metamorphic Binary Transformation Engine},
  author = {Marc Rivero},
  year = {2025},
  url = {https://github.com/seifreed/r2morph}
}
```

---
