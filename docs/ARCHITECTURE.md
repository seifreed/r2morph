# r2morph Architecture

## Overview

r2morph is a binary mutation and obfuscation framework built on radare2.
It disassembles executable binaries, applies semantics-preserving mutations
(instruction substitution, dead code injection, control flow flattening, etc.),
validates correctness, and writes the transformed binary back to disk.

## Layer Diagram

```
┌─────────────────────────────────────┐
│  cli.py / tui.py                    │  User-facing entry points
├─────────────────────────────────────┤
│  reporting/                         │  Report building, rendering, SARIF
├─────────────────────────────────────┤
│  validation/                        │  Semantic + structural validators
├─────────────────────────────────────┤
│  mutations/                         │  Mutation passes (obfuscation logic)
├─────────────────────────────────────┤
│  analysis/                          │  CFG, liveness, SSA, dataflow, etc.
├─────────────────────────────────────┤
│  core/                              │  Binary, Engine, Function, Instruction
├─────────────────────────────────────┤
│  adapters/                          │  DisassemblerInterface ↔ r2pipe
├─────────────────────────────────────┤
│  protocols/                         │  Abstract Protocol definitions
└─────────────────────────────────────┘
```

Arrows point inward only: outer layers import inner layers.
Inner layers never import from outer layers.

## Dependency Rules

- `protocols/` has zero internal imports; it defines all Protocol ABCs.
- `adapters/` depends only on `protocols/` and external libs (r2pipe).
- `core/` depends on `adapters/` and `protocols/`. It uses TYPE_CHECKING
  guards for lazy imports to avoid pulling heavy modules at import time.
- `analysis/` depends on `core/` for Binary/Function data structures.
- `mutations/` depends on `core/` and `analysis/`; never on `validation/`
  or `reporting/`.
- `validation/` depends on `core/` and `analysis/`.
- `reporting/` depends on `core/` and `validation/`. It was extracted from
  `cli.py` and `engine.py` to isolate presentation logic.
- `cli.py` and `tui.py` are the outermost layer; they wire everything together.

## Key Abstractions

| Protocol | Location | Purpose |
|---|---|---|
| `DisassemblerInterface` | `adapters/disassembler.py` | r2pipe abstraction; enables mock-based testing without radare2 |
| `MutationPassProtocol` | `protocols/__init__.py` | Contract for mutation passes: `apply(binary) -> dict` |
| `BinaryAccessProtocol` | `protocols/__init__.py` | Composite read+write protocol for passes that transform binaries |
| `BinaryReaderProtocol` | `protocols/__init__.py` | Read-only binary access (functions, disasm, sections, bytes) |
| `BinaryWriterProtocol` | `protocols/__init__.py` | Write-only binary access (write bytes, NOP fill, save) |
| `ReportEmitterProtocol` | `protocols/__init__.py` | Emit and enforce report policies |
| `ValidatorProtocol` | `protocols/__init__.py` | Validate mutations against original binary |

## Module Responsibilities

### `core/`
Binary lifecycle (open/close/analyze via r2pipe), instruction and function
domain models, the `MorphEngine` orchestrator, assembly encoding with
fallbacks, reader/writer separation, and memory management for large binaries.

### `analysis/`
Static analysis passes: CFG construction, liveness analysis, SSA form,
def-use chains, dataflow analysis, register tracking, call graph, switch
table detection, and symbolic execution bridges (angr, Syntia).

### `mutations/`
Concrete mutation passes inheriting `MutationPass`: NOP insertion,
instruction substitution/expansion, dead code injection, block reordering,
control flow flattening, opaque predicates, register substitution, string
obfuscation, API hashing, code virtualization, and anti-disassembly.

### `validation/`
Post-mutation correctness checks: structural integrity validation, semantic
equivalence testing, CFG integrity verification, mutation fuzzing, leak
detection, performance regression benchmarks, and diff reporting.

### `reporting/`
Report building, filtering, rendering (console + SARIF), gate evaluation
(pass/fail thresholds), and summary aggregation. Extracted from CLI to
keep presentation separate from engine logic.

### `crypto/`
Self-contained AES-256 implementation used by string obfuscation passes.
Lives in its own package because obfuscation passes need encryption at
mutation time, and using a standalone implementation avoids adding a
runtime dependency on a full crypto library (e.g., `cryptography`).

### `adapters/`
Concrete implementations of `DisassemblerInterface`: `R2PipeAdapter` for
production use and `MockDisassembler` for tests. The adapter layer exists
so the rest of the codebase depends on the protocol, not on r2pipe directly.

### `protocols/`
Runtime-checkable `Protocol` classes for dependency inversion. All abstract
contracts live here so that any module can depend on protocols without
importing concrete implementations.

### `platform/`
Format-specific handlers for ELF, PE, and Mach-O binaries. Section
manipulation, header repair, and format-aware relocation support.

### `relocations/`
Code cave discovery, cave injection, reference updating, and relocation
management for binaries that grow during mutation.

### `detection/`
Obfuscation detection heuristics: control flow flattening detection,
entropy analysis, packer signature matching, and evasion scoring.

## Design Decisions

**Why the r2pipe adapter exists.**
Direct r2pipe calls are scattered across the codebase in early versions.
The adapter wraps r2pipe behind `DisassemblerInterface` so that (a) tests
run without a radare2 installation by injecting `MockDisassembler`, and
(b) the disassembler backend can be swapped without changing client code.

**Why reporting was extracted from CLI.**
The original `cli.py` mixed Click command definitions with report building,
filtering, and console rendering. Extracting `reporting/` lets the engine
produce structured report payloads that the CLI merely renders, and makes
report logic independently testable.

**Why AES lives in `crypto/`.**
String obfuscation passes encrypt literal strings into the mutated binary.
A minimal AES-256 ECB implementation avoids adding `cryptography` or
`pycryptodome` as a runtime dependency. The implementation is explicitly
documented as not suitable for production security -- it exists solely to
generate encrypted payloads for obfuscation.
