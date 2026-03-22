# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-01-XX

### Added

#### P0 Features - Foundation
- **Call Graph Construction** (`r2morph/analysis/call_graph.py`)
  - Inter-procedural call graph analysis
  - Direct and indirect call resolution
  - Recursive chain detection
  - DOT/JSON export formats

- **Type Inference Engine** (`r2morph/analysis/type_inference.py`)
  - Forward type propagation
  - Backward type refinement
  - Pointer alias analysis
  - Struct layout inference

- **ARM64/ARM32 Architecture Support** (`r2morph/mutations/equivalences/`)
  - ARM64 register classes and instruction rules
  - ARM32 register classes and instruction rules
  - ARM calling conventions (AAPCS64, AAPCS)

#### P1 Features - Enhanced Analysis
- **Data Flow Analysis** (`r2morph/analysis/dataflow.py`, `liveness.py`, `defuse.py`)
  - Backward liveness analysis
  - Reaching definitions
  - Definition-use chains
  - Register value range tracking

- **CFG-Aware Mutations** (`r2morph/mutations/cfg_aware.py`)
  - Critical node detection
  - Mutation exclusion zones
  - Edge sensitivity scoring

- **Extended Semantic Validation** (`r2morph/validation/extended_semantic.py`)
  - Increased bounded-step limit
  - Constraint caching
  - Inter-procedural validation

#### P2 Features - Quality & Performance
- **Parallel Mutation Execution** (`r2morph/mutations/parallel_executor.py`)
  - Function-level parallelism
  - Thread pool executor
  - Conflict detection
  - Progress reporting

- **Property-Based Testing** (`tests/property/`)
  - Hypothesis-based test strategies
  - Mutation invariants
  - Binary generators

- **Mutation Conflict Detection** (`r2morph/mutations/conflict_detector.py`)
  - Overlapping region detection
  - Semantic interference analysis
  - Resolution suggestions

#### P3 Features - UX & Integration
- **SARIF 2.1.0 Output** (`r2morph/reporting/sarif_formatter.py`)
  - Full SARIF schema compliance
  - CI/CD integration (GitHub Security, Azure DevOps, SonarQube)
  - Mutation result mapping
  - Validation failure reporting

- **Analysis Cache** (`r2morph/core/analysis_cache.py`)
  - Content-addressable storage
  - Binary hash-based keys
  - Size limits with LRU eviction
  - Statistics tracking

- **Interactive TUI** (`r2morph/tui.py`)
  - Function selection screen
  - Pass selection with descriptions
  - Before/after disassembly preview
  - Mutation confirmation workflow

#### Validation Features
- **Mutation Fuzzer** (`r2morph/validation/mutation_fuzzer.py`)
  - Multiple input generators
  - Continuous fuzzing framework
  - Regression detection

- **Performance Regression Tests** (`r2morph/validation/performance_regression.py`)
  - Execution time measurement
  - Memory usage tracking
  - Baseline comparison

- **Memory Leak Detection** (`r2morph/validation/leak_detection.py`)
  - Memory growth detection
  - Object count tracking
  - GC pressure monitoring

#### Documentation
- **Examples** (`examples/`)
  - `basic_usage.py` - Basic mutation workflow
  - `mutation_workflow.py` - Pass configuration
  - `validation_example.py` - Validation capabilities
  - `custom_pass.py` - Creating custom passes

- **API Documentation** (`docs/API.md`)
  - Complete API reference
  - Code examples
  - Architecture diagram

#### CI/CD
- **GitHub Actions** (`.github/workflows/`)
  - Cross-platform tests (Ubuntu, macOS, Windows)
  - Python 3.11, 3.12, 3.13 support
  - Coverage reporting with Codecov
  - Release automation workflow
  - PyPI publishing

### Changed
- Improved ARM64 support in register substitution
- Fixed YAML parsing in arm64_rules.yaml
- Enhanced CLI with `--format sarif` and `--cache` options
- Updated support matrix documentation

### Fixed
- ARM64 instruction substitution now handles conditional instructions
- Register substitution uses correct caller_saved/callee_saved classes

## [0.1.0] - 2024-XX-XX

### Added
- Initial release
- Core mutation passes (nop, substitute, register)
- Structural validation
- Basic CLI
- ELF x86_64 support