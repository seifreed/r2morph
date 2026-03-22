# r2morph Feature Roadmap

**Version:** 2.0.0
**Created:** 2026-03-19
**Status:** Active Development

---

## Priority Overview

| Priority | Feature | Impact | Effort | Status |
|----------|---------|--------|--------|--------|
| P0 | ARM64/ARM32 Support | High | Large | Pending |
| P0 | Call Graph Construction | High | Medium | Pending |
| P0 | Type Inference Engine | High | Large | Pending |
| P1 | Data Flow Analysis | High | Large | Pending |
| P1 | CFG-Aware Mutations | Medium | Medium | Pending |
| P1 | Extended Symbolic Validation | High | Large | Pending |
| P2 | Parallel Execution | Medium | Medium | Pending |
| P2 | Property-Based Testing | Medium | Small | Pending |
| P2 | Mutation Conflict Detection | Medium | Medium | Pending |
| P3 | Interactive TUI | Low | Medium | Pending |
| P3 | SARIF Output (v2.1.0) | Low | Small | Pending |
| P3 | Analysis Cache | Medium | Medium | Pending |

---

## Phase 1: Foundation (P0 - High Impact)

### 1.1 Call Graph Construction

**Goal:** Build inter-procedural call graphs for enhanced analysis.

**Files to Create:**
- `r2morph/analysis/call_graph.py` - Main call graph module
- `r2morph/analysis/indirect_calls.py` - Indirect call analysis
- `tests/unit/test_call_graph.py` - Unit tests
- `tests/integration/test_call_graph_integration.py` - Integration tests

**Implementation Steps:**
1. Create `CallGraph` class with directed graph representation
2. Extract direct calls from disassembly
3. Identify indirect calls (function pointers, vtables)
4. Build caller/callee relationships
5. Detect recursive call chains
6. Add cycle detection for mutual recursion
7. Export to DOT/JSON formats
8. Cache call graph results

**Key Classes:**
```python
class CallGraph:
    def build(self, binary: Binary) -> None
    def get_callers(self, func_addr: int) -> list[int]
    def get_callees(self, func_addr: int) -> list[int]
    def find_recursive_chains(self) -> list[list[int]]
    def get_entry_points(self) -> list[int]
    def to_dot(self) -> str
    def to_json(self) -> dict

class CallNode:
    address: int
    name: str
    call_type: CallType  # DIRECT, INDIRECT, TAIL
    targets: list[int]
    callers: list[int]
```

**Dependencies:** None (foundational)

---

### 1.2 Type Inference Engine

**Goal:** Infer data types for safer mutations.

**Files to Create:**
- `r2morph/analysis/type_inference.py` - Type inference
- `r2morph/analysis/pointer_analysis.py` - Pointer aliasing
- `r2morph/analysis/struct_layout.py` - Structure layout inference
- `tests/unit/test_type_inference.py`
- `tests/unit/test_pointer_analysis.py`

**Implementation Steps:**
1. Define `TypeInfo` hierarchy (primitive, pointer, array, struct)
2. Implement forward type propagation
3. Implement backward type refinement
4. Add pointer alias analysis
5. Infer struct layouts from access patterns
6. Detect array bounds
7. Type-based mutation safety scoring

**Key Classes:**
```python
class TypeInfo:
    type_id: TypeId
    size: int
    alignment: int
    category: TypeCategory  # PRIMITIVE, POINTER, ARRAY, STRUCT

class TypeInference:
    def infer_type(self, addr: int, binary: Binary) -> TypeInfo
    def propagate_types(self, func: Function) -> dict[int, TypeInfo]
    def refine_types(self, context: InferenceContext) -> None

class PointerAnalysis:
    def compute_aliases(self, binary: Binary) -> dict[int, set[int]]
    def get_points_to(self, addr: int) -> set[int]
```

**Dependencies:** Call Graph (1.1)

---

### 1.3 ARM64/ARM32 Architecture Support

**Goal:** Full mutation support for ARM architectures.

**Files to Create/Modify:**
- `r2morph/mutations/equivalences/arm64_rules.yaml` - ARM64 rules
- `r2morph/mutations/equivalences/arm32_rules.yaml` - ARM32 rules
- `r2morph/mutations/arm64_rules.py` - ARM64 Python helpers
- `r2morph/mutations/arm32_rules.py` - ARM32 Python helpers
- `r2morph/core/constants.py` - Add ARM constants
- `r2morph/validation/validator.py` - ARM validation support
- `tests/fixtures/arm64/` - ARM64 test binaries
- `tests/fixtures/arm32/` - ARM32 test binaries

**Implementation Steps:**
1. Define ARM64 register classes (X0-X30, SP, PC, FP, LR)
2. Define ARM32 register classes (R0-R15, SP, LR, PC)
3. Add ARM calling conventions (AAPCS64, AAPCS)
4. Create ARM NOP equivalents
5. Add ARM instruction substitution rules
6. Handle ARM conditional instructions
7. Handle Thumb mode (ARM32)
8. Add ARM-specific validation

**Key Components:**
```python
class ARM64Rules:
    REGISTERS = ["x0", "x1", ..., "x30", "sp", "pc"]
    CALLER_SAVED = ["x0"-"x18"]
    CALLEE_SAVED = ["x19"-"x30"]
    NOP_EQUIVALENTS = [
        ("mov x0, x0", 4),
        ("add x0, x0, #0", 4),
        ("ldr x0, [sp]", 4),  # If safe
    ]

class ARM32Rules:
    REGISTERS = ["r0", "r1", ..., "r15", "sp", "lr", "pc"]
    THUMB_MODE = True  # Support Thumb-2
```

**Dependencies:** Type Inference (for safe mutations)

---

## Phase 2: Enhanced Analysis (P1)

### 2.1 Data Flow Analysis

**Goal:** Track value flow for safer mutations.

**Files to Create:**
- `r2morph/analysis/dataflow.py` - Liveness and reaching definitions
- `r2morph/analysis/liveness.py` - Register liveness
- `r2morph/analysis/defuse.py` - Definition-use chains
- `tests/unit/test_dataflow.py`

**Implementation Steps:**
1. Implement backward liveness analysis
2. Compute reaching definitions
3. Build definition-use chains
4. Track register value ranges
5. Score mutation safety by liveness
6. Generate mutation recommendations

**Key Classes:**
```python
class LivenessAnalysis:
    def compute_live_in(self, block: BasicBlock) -> set[Register]
    def compute_live_out(self, block: BasicBlock) -> set[Register]
    def is_live_at(self, reg: Register, addr: int) -> bool

class ReachingDefinitions:
    def compute_gen_kill(self, block: BasicBlock) -> tuple[set, set]
    def compute_in_out(self, func: Function) -> dict[int, set[Definition]]
    def get_reaching(self, addr: int) -> set[Definition]

class DefUseChain:
    definition: Definition
    uses: list[Use]
    reg: Register
    live_range: tuple[int, int]
```

**Dependencies:** Call Graph (1.1), Type Inference (1.2)

---

### 2.2 CFG-Aware Mutations

**Goal:** Avoid mutating critical control flow points.

**Files to Create:**
- `r2morph/mutations/cfg_aware.py` - CFG-aware mutation base
- Modify existing mutation passes for CFG awareness

**Implementation Steps:**
1. Define `CFGAwareMutationPass` base class
2. Implement critical node detection
3. Add edge sensitivity scoring
4. Create mutation exclusion zones
5. Update existing passes to use CFG context
6. Add CFG-based mutation recommendations

**Key Classes:**
```python
class CFGAwareMutationPass(MutationPass):
    def get_critical_nodes(self, cfg: CFG) -> set[int]
    def score_mutation_site(self, addr: int, cfg: CFG) -> float
    def should_skip(self, addr: int, cfg: CFG) -> bool
    def get_safe_regions(self, cfg: CFG) -> list[AddressRange]

class CriticalNodeDetector:
    def find_branch_targets(self, cfg: CFG) -> set[int]
    def find_call_sites(self, cfg: CFG) -> set[int]
    def find_entry_exits(self, cfg: CFG) -> set[int]
```

**Dependencies:** Data Flow Analysis (2.1)

---

### 2.3 Extended Semantic Validation

**Goal:** Validate larger code regions symbolically.

**Files to Modify:**
- `r2morph/validation/semantic.py` - Extend scope
- `r2morph/analysis/symbolic/` - Improve coverage

**Implementation Steps:**
1. Extend bounded step limit
2. Add constraint caching
3. Improve path explosion handling
4. Add loop unrolling support
5. Add inter-procedural validation
6. Improve state merging

**Key Enhancements:**
```python
class ExtendedSemanticValidator(SemanticValidator):
    def validate_function_semantics(self, binary: Binary, func: Function) -> ValidationResult
    def validate_loop_semantics(self, binary: Binary, loop: Loop) -> ValidationResult
    def validate_call_chain(self, binary: Binary, chain: list[int]) -> ValidationResult
    
    # New configuration
    max_states: int = 10000  # Increased from 1000
    use_constraint_cache: bool = True
    merge_interval: int = 100  # State merging frequency
```

**Dependencies:** Call Graph (1.1), Type Inference (1.2)

---

## Phase 3: Quality & Performance (P2)

### 3.1 Parallel Mutation Execution

**Goal:** Speed up mutations on multi-core systems.

**Files to Create:**
- `r2morph/core/parallel_executor.py` - Parallel execution engine
- `tests/unit/test_parallel_executor.py`

**Implementation Steps:**
1. Create function-level parallelism
2. Divide binary into independent chunks
3. Execute mutations in parallel
4. Merge results with conflict detection
5. Handle pass dependencies
6. Add progress reporting

**Key Classes:**
```python
class ParallelMutator:
    def __init__(self, max_workers: int = cpu_count())
    def mutate_functions_parallel(self, binary: Binary, funcs: list[Function]) -> dict[int, Result]
    def merge_results(self, results: list[Result]) -> Binary
    def execute_passes_parallel(self, passes: list[MutationPass]) -> list[Result]

class MutationTask:
    function: Function
    passes: list[MutationPass]
    dependencies: list[int]  # Function addresses that must complete first
```

**Dependencies:** Call Graph (1.1) for dependencies

---

### 3.2 Property-Based Testing

**Goal:** Auto-generate test cases for mutations.

**Files to Create:**
- `tests/property/test_mutation_properties.py` - Hypothesis tests
- `tests/property/strategies.py` - Test strategies
- `tests/property/invariants.py` - Mutation invariants

**Implementation Steps:**
1. Install Hypothesis
2. Create instruction sequence strategies
3. Define mutation invariants
4. Create binary generators
5. Add to CI pipeline

**Key Tests:**
```python
from hypothesis import given, strategies as st

@given(instruction_sequence(), mutation_seed())
def test_mutation_preserves_exit_code(instrs, seed):
    original = assemble(instrs)
    mutated = apply_mutation(original, seed)
    assert run_binary(original).exit_code == run_binary(mutated).exit_code

@given(function_with_loops(), mutation_pass())
def test_loop_semantics_preserved(func, pass):
    original_result = execute_function(func)
    mutated = pass.apply(func)
    mutated_result = execute_function(mutated)
    assert original_result == mutated_result
```

**Dependencies:** None

---

### 3.3 Mutation Conflict Detection

**Goal:** Prevent interfering mutations.

**Files to Create:**
- `r2morph/mutations/conflict_detector.py` - Conflict detection
- `tests/unit/test_conflict_detector.py`

**Implementation Steps:**
1. Track mutation regions
2. Detect overlapping regions
3. Identify read-after-write conflicts
4. Detect semantic interference
5. Provide resolution suggestions

**Key Classes:**
```python
class ConflictDetector:
    def detect_overlaps(self, mutations: list[AppliedMutation]) -> list[OverlapConflict]
    def find_interferences(self, mutations: list[AppliedMutation]) -> list[SemanticConflict]
    def suggest_resolution(self, conflicts: list[Conflict]) -> list[Resolution]

class MutationRegion:
    start: int
    end: int
    pass_name: str
    affected_registers: set[Register]
    affected_memory: set[int]
    control_flow_changed: bool
```

**Dependencies:** Data Flow Analysis (2.1)

---

## Phase 4: UX & Integration (P3)

### 4.1 SARIF Output Format (v2.1.0)

**Goal:** Export results in SARIF 2.1.0 format for CI/CD integration.

**Files to Create:**
- `r2morph/reporting/sarif_formatter.py` - SARIF formatting
- `r2morph/reporting/sarif_schema.py` - Schema validation
- `tests/unit/test_sarif_formatter.py`

**Implementation Steps:**
1. Define SARIF 2.1.0 schema compliance
2. Map mutation results to SARIF rules
3. Include locations with artifacts
4. Add fix suggestions
5. Support incremental results
6. Add CLI `--format sarif` option

**SARIF 2.1.0 Schema:**
```python
@dataclass
class SARIFReport:
    schema_uri: str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    version: str = "2.1.0"
    runs: list[SARIFRun]

@dataclass
class SARIFRun:
    tool: SARIFTool
    results: list[SARIFResult]
    artifacts: list[SARIFArtifact]

@dataclass
class SARIFResult:
    rule_id: str
    rule_index: int
    level: str  # "error", "warning", "note"
    message: SARIFMessage
    locations: list[SARIFLocation]
    fixes: list[SARIFFix] | None

@dataclass
class SARIFLocation:
    physical_location: SARIFPhysicalLocation
    
@dataclass
class SARIFPhysicalLocation:
    artifact_location: SARIFArtifactLocation
    region: SARIFRegion

@dataclass
class SARIFRegion:
    start_line: int
    start_column: int | None
    end_line: int | None
    end_column: int | None
    byte_offset: int | None
    byte_length: int | None
    snippet: SARIFSnippet | None
```

**CLI Usage:**
```bash
r2morph mutate input.bin -o output.bin --report report.json --format sarif
r2morph validate original.bin mutated.bin --format sarif -o results.sarif
```

**Dependencies:** None

---

### 4.2 Analysis Cache

**Goal:** Cache analysis results for faster repeated runs.

**Files to Create:**
- `r2morph/core/analysis_cache.py` - Cache management
- `r2morph/core/cache_storage.py` - Storage backends
- `tests/unit/test_analysis_cache.py`

**Implementation Steps:**
1. Define cache key schema (binary hash + options)
2. Implement disk-based storage
3. Track analysis dependencies
4. Implement selective invalidation
5. Add cache statistics
6. Add `--cache` and `--clear-cache` CLI options

**Key Classes:**
```python
class AnalysisCache:
    def __init__(self, cache_dir: Path | None = None)
    def get(self, binary: Binary, analysis_type: str) -> Any | None
    def set(self, binary: Binary, analysis_type: str, result: Any) -> None
    def invalidate(self, binary: Binary) -> None
    def invalidate_region(self, addr: int, size: int) -> None
    def get_stats(self) -> CacheStats

class CacheKey:
    binary_hash: str
    analysis_type: str
    options_hash: str
    version: str  # r2morph version
```

**Dependencies:** None

---

### 4.3 Interactive TUI

**Goal:** Provide interactive mutation selection.

**Files to Create:**
- `r2morph/cli/tui.py` - TUI implementation
- `r2morph/cli/tui_screens.py` - Screen definitions
- `tests/unit/test_tui.py`

**Implementation Steps:**
1. Create mutation preview screen
2. Add function selection interface
3. Show before/after disassembly
4. Add pass selection with descriptions
5. Implement confirmation workflow
6. Add progress indicator

**Key Components:**
```python
class MutationTUI:
    def run(self, binary: Binary) -> TUIResult
    def show_preview(self, mutation: Mutation) -> None
    def select_functions(self, funcs: list[Function]) -> list[Function]
    def select_passes(self) -> list[str]
    def confirm_mutations(self, plan: MutationPlan) -> bool

class TUIMainScreen(Screen):
    def render(self) -> None
    def handle_input(self, key: str) -> str

class TUIMutationPreview(Screen):
    def show_function_diff(self, addr: int) -> None
    def show_byte_diff(self, addr: int) -> None
    def show_semantic_check(self, check: str) -> None
```

**Dependencies:** SARIF (for export)

---

## Dependency Graph

```
Phase 1 (P0) Foundation:
    Call Graph ─┬──► Type Inference ─┬──► Data Flow Analysis
                 │                      │
                 │                      └──► CFG-Aware Mutations
                 │
                 └──► ARM Support ─────► Extended Symbolic
                              │
                              └──► Parallel Execution (independent)

Phase 2 (P1) Enhanced Analysis:
    Data Flow ──────► Conflict Detection
    CFG-Aware ──────► (all mutation passes enhanced)
    Extended Sym ───► Property-Based Testing

Phase 3 (P2) Quality:
    Parallel ───────► Analysis Cache
    Prop-Based ──────► (improves all tests)
    Conflict ───────► (improves mutation pipeline)

Phase 4 (P3) Integration:
    SARIF ──────────► (CI/CD integration)
    Cache ──────────► (performance)
    TUI ─────────────► (user experience)
```

---

## Timeline Estimates

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Phase 1.1 (Call Graph) | 2-3 weeks | None |
| Phase 1.2 (Type Inference) | 4-6 weeks | Call Graph |
| Phase 1.3 (ARM Support) | 6-8 weeks | Type Inference |
| Phase 2.1 (Data Flow) | 4-5 weeks | Type Inference |
| Phase 2.2 (CFG-Aware) | 2-3 weeks | Data Flow |
| Phase 2.3 (Extended Symbolic) | 4-6 weeks | Call Graph |
| Phase 3.1 (Parallel) | 2-3 weeks | Call Graph |
| Phase 3.2 (Property-Based) | 1-2 weeks | None |
| Phase 3.3 (Conflict Detection) | 2-3 weeks | Data Flow |
| Phase 4.1 (SARIF) | 1-2 weeks | None |
| Phase 4.2 (Cache) | 2-3 weeks | None |
| Phase 4.3 (TUI) | 3-4 weeks | SARIF |

**Total Estimated Duration:** 30-45 weeks

---

## Testing Strategy

Each feature requires:

1. **Unit Tests:** `tests/unit/test_<feature>.py`
2. **Integration Tests:** `tests/integration/test_<feature>_integration.py`
3. **Property Tests:** `tests/property/test_<feature>_properties.py` (Phase 3+)
4. **Documentation:** Code docstrings + type hints
5. **CLI Tests:** `tests/unit/test_cli_<feature>.py` (if applicable)

---

## Success Criteria

| Feature | Success Metric |
|---------|----------------|
| Call Graph | Correctly identifies all calls in test binaries |
| Type Inference | 95%+ accuracy on known types |
| ARM Support | All mutation passes work on ARM binaries |
| Data Flow | Correctly tracks all register values |
| CFG-Aware | 0% mutations break control flow |
| Extended Symbolic | Validates full functions |
| Parallel | 3x+ speedup on 4+ cores |
| Property-Based | Discovers edge cases not covered by unit tests |
| Conflict Detection | 0% mutation conflicts in test suite |
| SARIF | Validated against official schema |
| Cache | 10x+ speedup on repeated analysis |
| TUI | Usable without documentation |

---

## Implementation Order

### Sprint 1-2: Call Graph & Type Inference Foundation
1. Implement Call Graph construction
2. Add tests for call graph
3. Start Type Inference engine
4. Add basic type propagation

### Sprint 3-4: Complete Type Inference & Start ARM
1. Finish Type Inference
2. Start ARM64 register classes
3. Begin ARM instruction rules

### Sprint 5-6: ARM Support & Data Flow
1. Complete ARM support
2. Start Data Flow analysis
3. Implement liveness analysis

### Sprint 7-8: CFG-Aware & Extended Symbolic
1. Implement CFG-aware mutation base
2. Extend symbolic validation
3. Update existing passes for CFG awareness

### Sprint 9-10: Quality Features
1. Implement Parallel execution
2. Add Property-based testing
3. Implement Conflict detection

### Sprint 11-12: UX & Integration
1. Add SARIF output
2. Implement Analysis cache
3. Create Interactive TUI

---

*Document version: 1.0*
*Last updated: 2026-03-19*