# r2morph API Documentation

## Overview

r2morph is a metamorphic mutation engine for binary transformation. The API is organized into several modules:

- **Core**: Binary loading, engine, configuration
- **Mutations**: Mutation passes for binary transformation
- **Analysis**: Binary analysis utilities
- **Validation**: Validation and testing framework
- **Reporting**: SARIF and report generation
- **CLI**: Command-line interface (TUI)

## Quick Start

```python
from r2morph.core.engine import MorphEngine
from r2morph.core.config import EngineConfig

# Create engine with default configuration
config = EngineConfig.create_default()

with MorphEngine(config=config) as engine:
    # Load and analyze binary
    engine.load_binary("input.bin")
    engine.analyze()
    
    # Add mutation passes
    engine.add_mutation("nop")
    engine.add_mutation("substitute")
    engine.add_mutation("register")
    
    # Run with validation
    result = engine.run(validation_mode="structural")
    
    # Save mutated binary
    engine.save("output.bin")
    
    # Generate report
    report = engine.build_report(result)
```

## Core Modules

### `r2morph.core.engine`

The `MorphEngine` is the main entry point for binary mutation.

```python
from r2morph.core.engine import MorphEngine

class MorphEngine:
    """Main mutation engine."""
    
    def load_binary(self, path: Path | str) -> MorphEngine:
        """Load binary file for analysis."""
        
    def analyze(self) -> MorphEngine:
        """Analyze loaded binary."""
        
    def add_mutation(self, mutation: str) -> MorphEngine:
        """Add mutation pass by name."""
        
    def add_mutation_pass(self, mutation_pass: MutationPass) -> MorphEngine:
        """Add custom mutation pass instance."""
        
    def run(self, validation_mode: str = "structural") -> EngineResult:
        """Execute mutation pipeline."""
        
    def save(self, path: Path | str) -> None:
        """Save mutated binary."""
        
    def build_report(self, result: EngineResult) -> dict:
        """Build JSON report from result."""
```

### `r2morph.core.config`

Configuration classes for engine and mutation passes.

```python
from r2morph.core.config import (
    EngineConfig,
    NopInsertionConfig,
    InstructionSubstitutionConfig,
    RegisterSubstitutionConfig,
)

# Create default configuration
config = EngineConfig.create_default()

# Create aggressive configuration (more mutations)
config = EngineConfig.create_aggressive()

# Custom configuration
config = EngineConfig(
    nop=NopInsertionConfig(max_nop_sequences=10, probability=0.3),
    substitution=InstructionSubstitutionConfig(preserve_semantics=True),
    register=RegisterSubstitutionConfig(preserve_calling_convention=True),
)
```

### `r2morph.core.binary`

Binary representation and manipulation.

```python
from r2morph.core.binary import Binary

class Binary:
    """Loaded binary representation."""
    
    architecture: str          # e.g., "x86_64", "arm64"
    format: str               # e.g., "elf", "pe", "mach-o"
    functions: list[Function] # Parsed functions
    sections: list[Section]   # Binary sections
    
    def get_function(self, address: int) -> Function | None:
        """Get function at address."""
```

## Mutation Modules

### `r2morph.mutations.base`

Base classes for mutation passes.

```python
from r2morph.mutations.base import MutationPass, MutationResult, MutationRecord

class MutationPass(ABC):
    """Base class for all mutation passes."""
    
    name: str                    # Pass identifier
    architectures: tuple[str]    # Supported architectures
    formats: tuple[str]          # Supported formats
    
    @abstractmethod
    def apply(self, binary: Binary, context: dict | None = None) -> MutationResult:
        """Apply mutation to binary."""
```

### Stable Mutation Passes

```python
from r2morph.mutations import (
    NopInsertionPass,              # Insert NOP instructions
    InstructionSubstitutionPass,   # Replace with equivalent instructions
    RegisterSubstitutionPass,      # Substitute registers
)

# Usage
engine.add_mutation("nop")         # NOP insertion
engine.add_mutation("substitute")  # Instruction substitution
engine.add_mutation("register")    # Register substitution
```

### Experimental Mutation Passes

```python
from r2morph.mutations import (
    BlockReorderingPass,        # Reorder basic blocks
    DeadCodeInjectionPass,      # Inject dead code
    ControlFlowFlatteningPass,  # Flatten control flow
    InstructionExpansionPass,   # Expand instructions
    OpaquePredicatesPass,       # Add opaque predicates
)

# Usage (experimental - best-effort support)
engine.add_mutation("block")      # Block reordering
engine.add_mutation("dead-code")  # Dead code injection
engine.add_mutation("cff")        # Control flow flattening
```

### New Mutation Passes (P2/P3)

```python
from r2morph.mutations import (
    DataFlowMutationPass,       # Data flow-aware mutations
    StringObfuscationPass,       # String obfuscation
    ImportTableObfuscationPass,  # Import table obfuscation
    ConstantUnfoldingPass,       # Constant unfolding
)

from r2morph.mutations.parallel_executor import ParallelMutator

# Parallel execution
mutator = ParallelMutator(max_workers=4)
results = mutator.mutate_functions_parallel(binary, functions)
```

## Analysis Modules

### `r2morph.analysis.call_graph`

Call graph construction for inter-procedural analysis.

```python
from r2morph.analysis import CallGraph, CallGraphBuilder

builder = CallGraphBuilder(binary)
call_graph = builder.build()

# Get callers/callees
callers = call_graph.get_callers(func_address)
callees = call_graph.get_callees(func_address)

# Find recursive chains
recursive = call_graph.find_recursive_chains()

# Export to DOT format
dot = call_graph.to_dot()
```

### `r2morph.analysis.type_inference`

Type inference engine for safer mutations.

```python
from r2morph.analysis import TypeInference, TypeInfo, TypeCategory

inference = TypeInference()
types = inference.propagate_types(binary, function)

# Get type at address
type_info = inference.infer_type(address, binary)
# type_info.category: PRIMITIVE, POINTER, ARRAY, STRUCT
```

### `r2morph.analysis.dataflow`

Data flow analysis for mutation safety.

```python
from r2morph.analysis import DataFlowAnalyzer, LivenessAnalysis

# Data flow analysis
analyzer = DataFlowAnalyzer(binary)
result = analyzer.analyze(function)

# Liveness analysis
liveness = LivenessAnalysis()
live_registers = liveness.compute_live_out(block)
```

## Validation Modules

### `r2morph.validation`

Comprehensive validation framework.

```python
from r2morph.validation import BinaryValidator, ValidationManager

# Direct validation
validator = BinaryValidator(binary_path)
is_valid = validator.validate()

# Validation manager
manager = ValidationManager()
result = manager.validate(original, mutated, mode="structural")
```

### `r2morph.validation.mutation_fuzzer`

Fuzz testing for mutation passes.

```python
from r2morph.validation import MutationPassFuzzer, FuzzConfig

config = FuzzConfig(seed=42, num_cases=100)
fuzzer = MutationPassFuzzer(config)

results = fuzzer.fuzz_mutations(pass_config)
```

### `r2morph.validation.leak_detection`

Memory and resource leak detection.

```python
from r2morph.validation import MemoryLeakDetector

detector = MemoryLeakDetector()
result = detector.test_function(lambda: mutation.apply(binary))

# Check for leaks
if result.leaks_detected:
    print(f"Memory leak: {result.bytes_leaked} bytes")
```

## Reporting Modules

### `r2morph.reporting.sarif_formatter`

SARIF 2.1.0 output for CI/CD integration.

```python
from r2morph.reporting import SARIFFormatter, ReportData, MutationResult

# Create formatter
formatter = SARIFFormatter(tool_version="0.2.0")

# Build report data
report_data = ReportData(
    binary_path="input.bin",
    output_path="output.bin",
    mutations=[...],
    validations=[...],
)

# Generate SARIF
sarif_report = formatter.format(report_data)
sarif_json = formatter.to_json(report_data)

# Save to file
formatter.to_file(report_data, "report.sarif")
```

### `r2morph.core.analysis_cache`

Analysis result caching.

```python
from r2morph.core import AnalysisCache, CacheStats

# Create cache
cache = AnalysisCache(cache_dir=".cache/r2morph")

# Cache analysis result
cache.set(binary_data=binary_bytes, analysis_type="cfg", result=cfg_result)

# Retrieve cached result
cached = cache.get(binary_data=binary_bytes, analysis_type="cfg")

# Get statistics
stats = cache.get_stats()
print(f"Hit rate: {stats.hit_rate:.2%}")
```

## TUI Module

### `r2morph.tui`

Interactive terminal UI for mutation selection.

```python
from r2morph.tui import (
    MutationTUI,
    TUIFunction,
    TUIPass,
    create_default_passes,
)

# Create TUI
tui = MutationTUI()

# Define functions
functions = [
    TUIFunction(address=0x1000, name="main", size=256),
    TUIFunction(address=0x2000, name="helper", size=128),
]

# Define passes
passes = create_default_passes()

# Run interactive session
result = tui.run(functions, passes, on_execute=my_callback)

if result and result.confirmed:
    print("User confirmed mutations")
```

## Examples

See the `examples/` directory:

- `basic_usage.py` - Basic mutation workflow
- `mutation_workflow.py` - Working with different passes
- `validation_example.py` - Validation capabilities
- `custom_pass.py` - Creating custom mutation passes
- `advanced_mutations.py` - Advanced mutation techniques
- `comprehensive_validation.py` - Full validation suite

## Architecture

```
r2morph/
├── core/           # Core binary handling
│   ├── binary.py   # Binary representation
│   ├── engine.py   # Mutation engine
│   ├── config.py   # Configuration
│   └── analysis_cache.py  # Caching
├── mutations/      # Mutation passes
│   ├── base.py     # Base classes
│   ├── nop_insertion.py
│   ├── instruction_substitution.py
│   ├── register_substitution.py
│   └── ...         # Other passes
├── analysis/       # Analysis utilities
│   ├── call_graph.py
│   ├── type_inference.py
│   ├── dataflow.py
│   └── ...         # Other analyses
├── validation/     # Validation framework
│   ├── manager.py
│   ├── fuzzer.py
│   └── ...         # Validators
├── reporting/       # Report generation
│   ├── sarif_formatter.py
│   └── sarif_schema.py
└── tui.py          # Terminal UI
```

## Version Information

```python
import r2morph
print(r2morph.__version__)  # Current version
```

## Support Matrix

| Feature | Status |
|---------|--------|
| ELF x86_64 | Stable |
| ELF arm64 | Stable |
| PE x86_64 | Experimental |
| Mach-O | Experimental |
| NOP insertion | Stable |
| Instruction substitution | Stable |
| Register substitution | Stable |
| Block reordering | Experimental |
| Dead code injection | Experimental |
| Control flow flattening | Experimental |