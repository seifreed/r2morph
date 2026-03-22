# ABI Invariant Enforcement Plan (Issue #5)

## Goal
Enforce ABI and calling convention invariants across ALL mutation passes, with regression tests and output prevention.

## Current State
| Component | Status | Gap |
|-----------|--------|-----|
| ABIChecker module | Done | - |
| ABI specs (x86_64, ARM64) | Done | - |
| Stack/Red zone/Shadow space checks | Done | - |
| Callee-saved register checks | Done | - |
| ValidationManager integration | Partial | Only some passes |
| Mutation pass hooks | Partial | 3 of N passes |
| Regression tests | Missing | Unit tests exist |
| Output prevention | Missing | Violations don't block save |
| Documentation | Missing | No hook docs |

## Implementation Plan

### Phase 1: Base ABI Hook Infrastructure
**File:** `r2morph/mutations/abi_hook.py`
- `ABIMutationHook` class for use in all passes
- Pre-mutation snapshot of ABI state
- Post-mutation validation
- Violation aggregation and reporting

### Phase 2: Integrate into All Mutation Passes
Files to update:
- `r2morph/mutations/block_reordering.py`
- `r2morph/mutations/control_flow_flattening.py`
- `r2morph/mutations/dead_code_injection.py`
- `r2morph/mutations/instruction_expansion.py`
- Any other mutation passes

Each pass gets:
- `self._abi_hook` initialization
- Pre-mutation ABI check
- Post-mutation ABI validation
- Violation handling

### Phase 3: Output Prevention
**File:** `r2morph/core/engine.py` or validation layer
- Block binary write if ABI violations detected
- Clear error message with violation details
- Option to force output with `--ignore-abi-violations`

### Phase 4: Regression Tests
**File:** `tests/integration/test_abi_regression.py`
- Test each mutation pass preserves ABI on real binaries
- Platform-specific tests (Linux x86_64, ARM64, Windows)
- Violation injection tests (verify detection works)

### Phase 5: Documentation
**File:** `docs/abi_hooks.md`
- How to add ABI checking to new passes
- Available checks and violations
- Configuration options
- Platform-specific behavior

## Acceptance Criteria
- [ ] All mutation passes have ABI hooks
- [ ] ABI violations block binary output
- [ ] Regression tests pass on all platforms
- [ ] Documentation exists
- [ ] Clear diagnostics on violation