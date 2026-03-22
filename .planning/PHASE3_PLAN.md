# Phase 3 Implementation Plan: Quality & Performance

**Status:** Pending
**Priority:** P2 (Medium)
**Estimated Duration:** 5-8 weeks

---

## Overview

Phase 3 focuses on improving quality and performance:
- **Parallel Execution** - Speed up mutations on multi-core systems
- **Property-Based Testing** - Auto-generate test cases
- **Mutation Conflict Detection** - Prevent interfering mutations

---

## 3.1 Parallel Mutation Execution

### Goal
Execute mutations in parallel across independent functions to improve performance on large binaries.

### Files to Create

```
r2morph/core/parallel_executor.py        # Parallel execution engine
r2morph/core/work_queue.py              # Work distribution
r2morph/core/result_merger.py           # Merge mutation results
tests/unit/test_parallel_executor.py    # Unit tests
tests/integration/test_parallel_mutate.py # Integration tests
```

### Key Classes

```python
class ParallelMutator:
    def __init__(self, max_workers: int = cpu_count())
    def mutate_functions_parallel(self, binary: Binary, funcs: list[Function]) -> dict[int, Result]
    def merge_results(self, results: list[Result]) -> Binary

class MutationTask:
    function: Function
    passes: list[MutationPass]
    dependencies: list[int]  # Function addresses that must complete first
    priority: int

class WorkQueue:
    def add_task(self, task: MutationTask) -> None
    def get_ready_tasks(self) -> list[MutationTask]
    def mark_complete(self, task_id: int) -> None
    def get_dependencies(self, task_id: int) -> list[int]

class ResultMerger:
    def merge(self, binary: Binary, results: list[MutationResult]) -> Binary
    def resolve_conflicts(self, conflicts: list[Conflict]) -> list[Resolution]
```

### Implementation Steps

1. **Work Distribution**
   - Identify independent functions (from call graph)
   - Create task dependency graph
   - Prioritize by function size/cost

2. **Parallel Execution**
   - Use ProcessPoolExecutor for CPU-bound work
   - Handle pass dependencies
   - Progress reporting

3. **Result Merging**
   - Merge binary changes safely
   - Resolve conflicts between mutations
   - Validate merged result

4. **Integration**
   - Add `--parallel` flag to CLI
   - Add `--workers N` option
   - Hook into existing pipeline

### Success Criteria

- 3x+ speedup on 4+ cores
- No correctness regressions
- Scales with core count
- Handles dependencies correctly

---

## 3.2 Property-Based Testing

### Goal
Use Hypothesis to automatically generate test cases for mutations.

### Files to Create

```
tests/property/test_mutation_properties.py    # Hypothesis tests
tests/property/test_semantic_properties.py     # Semantic invariants
tests/property/strategies.py                   # Hypothesis strategies
tests/property/invariants.py                   # Mutation invariants
```

### Key Components

```python
# strategies.py
from hypothesis import strategies as st

@st.composite
def instruction_sequence(draw):
    # Generate valid instruction sequences
    pass

@st.composite
def function_with_loops(draw):
    # Generate functions with various loop patterns
    pass

@st.composite
def binary_with_functions(draw):
    # Generate complete test binaries
    pass

# invariants.py
def test_mutation_preserves_exit_code(original: bytes, mutated: bytes) -> bool:
    # Property: exit code unchanged
    pass

def test_mutation_preserves_semantics(original: bytes, mutated: bytes) -> bool:
    # Property: semantic equivalence
    pass

def test_mutation_preserves_function_count(original: bytes, mutated: bytes) -> bool:
    # Property: same number of functions
    pass

# test_mutation_properties.py
from hypothesis import given, settings

@given(instruction_sequence(), mutation_seed())
@settings(max_examples=100)
def test_nop_insertion_preserves_semantics(instrs, seed):
    original = assemble(instrs)
    mutated = apply_nop_insertion(original, seed)
    assert semantics_equal(original, mutated)

@given(function_with_loops(), mutation_pass())
def test_mutation_preserves_loop_count(func, pass):
    original_loops = count_loops(func)
    mutated = pass.apply(func)
    mutated_loops = count_loops(mutated)
    assert original_loops == mutated_loops
```

### Implementation Steps

1. **Install Hypothesis**
   - Add to pyproject.toml
   - Create test infrastructure

2. **Create Strategies**
   - Instruction sequence generator
   - Binary generator
   - Function generator with various patterns

3. **Define Invariants**
   - Exit code preservation
   - Semantic equivalence
   - Function count
   - Control flow structure

4. **Create Tests**
   - Mutation property tests
   - Semantic property tests
   - Boundary case discovery

### Success Criteria

- All property tests pass
- Coverage >85%
- Discovers edge cases not in unit tests
- CI integration

---

## 3.3 Mutation Conflict Detection

### Goal
Detect and prevent conflicting mutations from being applied in the same region.

### Files to Create

```
r2morph/mutations/conflict_detector.py        # Conflict detection
r2morph/mutations/region_tracker.py           # Track mutation regions
r2morph/mutations/resolution.py               # Conflict resolution
tests/unit/test_conflict_detector.py          # Unit tests
```

### Key Classes

```python
class MutationRegion:
    start: int
    end: int
    pass_name: str
    affected_registers: set[Register]
    affected_memory: set[int]
    control_flow_changed: bool
    metadata: dict[str, Any]
    
    def overlaps(self, other: MutationRegion) -> bool
    def conflicts_with(self, other: MutationRegion) -> ConflictType

class ConflictDetector:
    def detect_overlaps(self, mutations: list[AppliedMutation]) -> list[OverlapConflict]
    def find_interferences(self, mutations: list[AppliedMutation]) -> list[SemanticConflict]
    def suggest_resolution(self, conflicts: list[Conflict]) -> list[Resolution]
    def validate_pipeline(self, passes: list[MutationPass]) -> list[Conflict]

class RegionTracker:
    def track_mutation(self, mutation: AppliedMutation) -> None
    def get_regions_at(self, addr: int) -> list[MutationRegion]
    def get_overlaps(self) -> list[tuple[MutationRegion, MutationRegion]]
    def clear_regions(self) -> None

class Resolution:
    conflict: Conflict
    strategy: ResolutionStrategy  # SKIP, REORDER, MERGE, ABORT
    description: str
```

### Implementation Steps

1. **Region Tracking**
   - Track where each mutation applies
   - Track register/memory modifications
   - Track control flow changes

2. **Overlap Detection**
   - Find overlapping regions
   - Classify by severity
   - Report to user

3. **Interference Analysis**
   - Detect register conflicts
   - Detect memory conflicts
   - Detect control flow conflicts

4. **Conflict Resolution**
   - Suggest optimal ordering
   - Suggest mutations to skip
   - Generate conflict report

### Success Criteria

- Detects all overlapping mutations
- Zero false positives
- Provides actionable resolutions
- Fast (<100ms for typical binary)

---

## Dependencies

```
Phase 1 (Call Graph)
    └── Phase 3.1 (Parallel Execution)
            
Phase 2.1 (Data Flow)
    └── Phase 3.3 (Conflict Detection)

Phase 1 (Type Inference)
    └── Phase 3.2 (Property Testing)
```

---

## Timeline

| Week | Task |
|------|------|
| 1-2 | Parallel Executor Core |
| 3-4 | Work Queue & Result Merging |
| 5-6 | Property-Based Testing Infrastructure |
| 7-8 | Conflict Detection & Resolution |
| 8 | Integration & Documentation |

---

*Created: 2026-03-19*