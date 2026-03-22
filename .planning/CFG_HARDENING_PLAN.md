# CFG Hardening Plan for Issue #3

## Goal
Harden control-flow mutations for complex CFGs by implementing:
1. Exception edge preservation
2. Dispatcher/jump table pattern preservation
3. CFG integrity checks
4. Regression tests with optimized binaries

## Current State Analysis

### Existing Components
| Component | File | Status |
|-----------|------|--------|
| Exception Info Reader | `analysis/exception.py` | Exists, reads but doesn't preserve |
| Switch Table Analyzer | `analysis/switch_table.py` | Exists, detects but doesn't preserve |
| CFG-Aware Mutations | `mutations/cfg_aware.py` | Basic critical node avoidance |
| Critical Node Detector | `analysis/critical_nodes.py` | Exists, not extended for all patterns |

### Gaps
1. Exception edges detected but not added to exclusion zones
2. Jump tables/switch tables not protected during mutations
3. PLT/GOT thunks not preserved by mutation passes
4. No CFG integrity validation after mutations
5. No integration with experimental passes (CFF, opaque predicates)

## Implementation Plan

### Phase 1: Pattern Preservation Framework
**File:** `r2morph/analysis/pattern_preservation.py`
- Define `PreservedPattern` dataclass (pattern type, address range, metadata)
- Define `PatternPreservationManager` to collect and query preserved patterns
- Support pattern types: EXCEPTION_LANDING_PAD, JUMP_TABLE, DISPATCHER, PLT_THUNK, TAIL_CALL

### Phase 2: Enhanced Critical Node Detector
**File:** `r2morph/analysis/critical_nodes.py` (extend existing)
- Add jump table detection to critical nodes
- Add exception landing pad detection
- Add PLT/GOT thunk detection
- Add dispatcher pattern detection (for virtualized handlers)

### Phase 3: CFG Integrity Checker
**File:** `r2morph/validation/cfg_integrity.py`
- `CFGIntegrityChecker` class
- Pre-mutation CFG snapshot
- Post-mutation CFG validation
- Check: reachability, edge preservation, jump targets, landing pads
- Generate integrity report

### Phase 4: Hardened Mutation Passes
**File:** `r2morph/mutations/hardened_base.py`
- `HardenedMutationPass` extending `CFGAwareMutationPass`
- Integrate `PatternPreservationManager`
- Integrate `CFGIntegrityChecker` (optional, for verification)
- Pre/post apply hooks for integrity checking

### Phase 5: Integration with Existing Passes
- Update `ControlFlowFlatteningPass` to use `HardenedMutationPass`
- Update `OpaquePredicatesPass` similarly
- Add preservation config to pass constructors

### Phase 6: Test Fixtures
**Directory:** `tests/fixtures/optimized_binaries/`
- Create small ELF x86_64 binaries with complex CFGs
- Include: switch statements, exception handling, PLT calls, tail calls
- Use compiler optimization flags (-O2, -O3)

### Phase 7: Regression Tests
**File:** `tests/integration/test_cfg_hardening.py`
- Test pattern preservation
- Test CFG integrity validation
- Test hardened mutations on complex binaries
- Test no regression on existing passes

## Detailed Implementation

### Pattern Types
```python
class PatternType(Enum):
    EXCEPTION_HANDLER = "exception_handler"
    LANDING_PAD = "landing_pad"
    JUMP_TABLE = "jump_table"
    SWITCH_DISPATCHER = "switch_dispatcher"
    VIRTUAL_DISPATCHER = "virtual_dispatcher"
    PLT_THUNK = "plt_thunk"
    GOT_ENTRY = "got_entry"
    TAIL_CALL = "tail_call"
    INDIRECT_JUMP = "indirect_jump"
```

### Preservation Zones
Each pattern creates an exclusion zone:
- Jump table: table address + all entry targets (prevent writes)
- Landing pad: landing pad address + size (preserve entry points)
- PLT thunk: thunk address + stub size (never modify)

### Integrity Checks
1. **Reachability** - all original reachable blocks still reachable
2. **Edge Preservation** - critical edges not broken
3. **Target Validity** - all jump targets valid
4. **Exception Safety** - landing pads reachable from protected regions

### Test Binaries
Create with minimal C programs compiled with optimization:
```c
// switch_complex.c
int process(int x) {
    switch(x) {
        case 0: return 1;
        case 1: return 2;
        case 2: return 3;
        // ... many cases
        default: return -1;
    }
}

// exception_test.cpp
void func() {
    try {
        throw std::runtime_error("test");
    } catch (...) {
        // handler
    }
}

// plt_calls.c
extern int external_func(int);
int caller() {
    return external_func(1) + external_func(2);
}

// tail_call.c
int helper(int x);
int entry(int x) {
    return helper(x); // tail call
}
```

## Acceptance Criteria

- [ ] Pattern preservation manager integrated
- [ ] Exception edges preserved during mutations
- [ ] Jump tables/dispatchers protected
- [ ] PLT/GOT thunks preserved
- [ ] CFG integrity validation available
- [ ] Tests pass for: Linux (ELF), macOS (Mach-O), Windows (PE)
- [ ] No regressions in existing integration tests
- [ ] Mutated binaries remain executable with matching outputs

## Timeline Estimate

| Phase | Effort |
|-------|--------|
| Phase 1: Pattern Preservation | 1-2 hours |
| Phase 2: Enhanced Critical Nodes | 1-2 hours |
| Phase 3: CFG Integrity Checker | 2-3 hours |
| Phase 4: Hardened Mutation Base | 1 hour |
| Phase 5: Pass Integration | 1 hour |
| Phase 6: Test Fixtures | 1 hour |
| Phase 7: Regression Tests | 1-2 hours |

**Total:** 8-12 hours

## Dependencies
- No new external dependencies
- Uses existing `analysis/exception.py`, `analysis/switch_table.py`
- Extends `mutations/cfg_aware.py`