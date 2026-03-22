# Phase 2 Implementation Plan: Enhanced Analysis

**Status:** In Progress
**Priority:** P1 (High)
**Estimated Duration:** 10-14 weeks

---

## Overview

Phase 2 focuses on enhanced analysis capabilities that improve mutation safety:
- **Data Flow Analysis** - Track value flow for safer mutations
- **CFG-Aware Mutations** - Avoid mutating critical control flow points
- **Extended Symbolic Validation** - Validate larger code regions

---

## 2.1 Data Flow Analysis

### Goal
Implement comprehensive data flow analysis including:
- Liveness analysis (what registers are live at each point)
- Reaching definitions (what definitions reach each point)
- Def-use chains (definition to use connections)

### Files to Create

```
r2morph/analysis/dataflow.py          # Core data flow engine
r2morph/analysis/liveness.py         # Liveness analysis
r2morph/analysis/defuse.py            # Def-use chains
r2morph/analysis/value_set.py         # Value set analysis
tests/unit/test_dataflow.py           # Unit tests
tests/unit/test_liveness.py           # Unit tests
tests/unit/test_defuse.py             # Unit tests
```

### Key Classes

```python
class LivenessAnalysis:
    def compute_live_in(self, block: BasicBlock) -> set[Register]
    def compute_live_out(self, block: BasicBlock) -> set[Register]
    def is_live_at(self, reg: Register, addr: int) -> bool
    def get_live_registers(self, func: Function) -> dict[int, set[Register]]

class ReachingDefinitions:
    def compute_gen_kill(self, block: BasicBlock) -> tuple[set, set]
    def compute_in_out(self, func: Function) -> dict[int, set[Definition]]
    def get_reaching(self, addr: int) -> set[Definition]

class DefUseChain:
    definition: Definition
    uses: list[Use]
    register: Register
    live_range: tuple[int, int]

class DataFlowAnalyzer:
    def analyze_function(self, binary: Binary, func: Function) -> DataFlowResult
    def get_value_at(self, addr: int, reg: Register) -> ValueSet
    def is_safe_to_mutate(self, addr: int, mutation: Mutation) -> tuple[bool, str]
```

### Implementation Steps

1. **Liveness Analysis**
   - Implement backward data flow analysis
   - Compute live-in and live-out sets for each block
   - Handle function calls (caller-saved registers)
   - Memory location liveness

2. **Reaching Definitions**
   - Implement forward data flow analysis
   - Track definitions that reach each point
   - Handle aliases and pointers
   - Build definition-use chains

3. **Value Set Analysis**
   - Compute possible values for each register
   - Track constant propagation
   - Handle unknown values

4. **Integration**
   - Connect with Type Inference (Phase 1)
   - Use with CFG analysis
   - Provide mutation safety scoring

### Success Criteria

- Correctly identifies live registers at each instruction
- Builds accurate def-use chains
- Provides mutation safety recommendations
- >90% accuracy on test binaries

---

## 2.2 CFG-Aware Mutations

### Goal
Create mutation passes that are aware of control flow graphs to avoid:
- Mutating near critical control flow points
- Breaking jump targets
- Modifying predicates incorrectly

### Files to Create/Modify

```
r2morph/mutations/cfg_aware.py              # CFG-aware mutation base
r2morph/mutations/cfg_aware_nop.py          # CFG-aware NOP insertion
r2morph/mutations/cfg_aware_substitution.py  # CFG-aware substitution
r2morph/analysis/critical_nodes.py           # Critical node detection
tests/unit/test_cfg_aware.py                 # Unit tests
```

### Key Classes

```python
class CriticalNodeDetector:
    def find_branch_targets(self, cfg: CFG) -> set[int]
    def find_call_sites(self, cfg: CFG) -> set[int]
    def find_entry_exits(self, cfg: CFG) -> set[int]
    def find_exception_handlers(self, cfg: CFG) -> set[int]
    def get_exclusion_zones(self, cfg: CFG) -> list[AddressRange]
    def get_safe_regions(self, cfg: CFG) -> list[AddressRange]

class CFGAwareMutationPass(MutationPass):
    def get_critical_nodes(self, cfg: CFG) -> set[int]
    def score_mutation_site(self, addr: int, cfg: CFG) -> float
    def should_skip(self, addr: int, cfg: CFG) -> bool
    def get_safe_regions(self, cfg: CFG) -> list[AddressRange]
    def apply_cfg_aware(self, binary: Binary, cfg: CFG) -> dict

class MutationSafetyScorer:
    def score_address(self, addr: int, cfg: CFG, dataflow: DataFlowResult) -> float
    def get_safest_addresses(self, func: Function, count: int) -> list[int]
```

### Implementation Steps

1. **Critical Node Detection**
   - Identify branches and jump targets
   - Find call instruction sites
   - Detect loop headers and back edges
   - Find exception handlers and landing pads

2. **Exclusion Zones**
   - Calculate exclusion regions around critical points
   - Define minimum safe distance from jumps
   - Handle overlapping exclusion zones

3. **Safety Scoring**
   - Score each address for mutation safety
   - Consider distance from critical nodes
   - Use data flow for additional safety

4. **CFG-Aware Passes**
   - Update existing mutation passes
   - Add CFG awareness option
   - Filter mutation sites based on CFG

### Success Criteria

- Zero mutations break control flow
- Safe regions correctly identified
- Mutation quality improved
- All tests pass with CFG awareness enabled

---

## 2.3 Extended Symbolic Validation

### Goal
Extend symbolic validation to handle:
- Larger code regions
- More instruction patterns
- Better state merging

### Files to Modify/Create

```
r2morph/validation/semantic.py              # Extend existing
r2morph/analysis/symbolic/path_explorer.py  # Improve path exploration
r2morph/analysis/symbolic/state_manager.py   # State management improvements
r2morph/analysis/symbolic/constraint_cache.py # NEW: Constraint caching
tests/unit/test_extended_symbolic.py          # Unit tests
```

### Key Enhancements

```python
class ExtendedSemanticValidator(SemanticValidator):
    # Configuration
    max_states: int = 10000            # Increased from 1000
    max_steps: int = 500               # Increased step limit
    use_constraint_cache: bool = True
    merge_interval: int = 100          # State merging frequency
    
    def validate_function_semantics(self, binary: Binary, func: Function) -> ValidationResult
    def validate_loop_semantics(self, binary: Binary, loop: Loop) -> ValidationResult
    def validate_call_chain(self, binary: Binary, chain: list[int]) -> ValidationResult

class ConstraintCache:
    def get(self, constraint: Constraint) -> Result | None
    def set(self, constraint: Constraint, result: Result) -> None
    def invalidate(self, addr: int) -> None

class ImprovedStateMerging:
    def merge_states(self, states: list[State]) -> State
    def find_merge_points(self, cfg: CFG) -> list[int]
    def should_merge(self, state1: State, state2: State) -> bool
```

### Implementation Steps

1. **Increase Limits**
   - Raise step limit to 500
   - Raise state limit to 10000
   - Add configurable limits

2. **Constraint Caching**
   - Cache solved constraints
   - Reuse across similar paths
   - Invalidate on mutation

3. **Better State Merging**
   - Implement k-lattice merging
   - Merge at loop headers
   - Handle function boundaries

4. **Pattern Coverage**
   - Add more equivalence patterns
   - Handle more ARM64 instructions
   - Improve jump table handling

### Success Criteria

- Validates functions up to 50 instructions
- Handles loops with bounded iterations
- Constraint cache hit rate >60%
- No false negatives on safe mutations

---

## Dependencies

```
Phase 1 (Call Graph + Type Inference)
    └── Phase 2.1 (Data Flow)
            └── Phase 2.2 (CFG-Aware)
                    └── Phase 2.3 (Extended Symbolic)
```

---

## Testing Strategy

Each feature requires:
1. Unit tests with >80% coverage
2. Integration tests with real binaries
3. Performance benchmarks
4. Regression tests for existing functionality

---

## Timeline

| Week | Task |
|------|------|
| 1-2 | Data Flow Analysis core |
| 3-4 | Liveness and Reaching Definitions |
| 5-6 | Def-Use Chains + Integration |
| 7-8 | Critical Node Detection |
| 9-10 | CFG-Aware Mutation Passes |
| 11-12 | Extended Symbolic Validation |
| 13-14 | Integration Testing + Documentation |

---

*Created: 2026-03-19*