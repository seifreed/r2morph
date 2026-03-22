# Deterministic Mutation Runs Plan (Issue #6)

## Goal
Make mutation runs deterministic and reproducible with full seed control.

## Current State Analysis

### Seed Infrastructure (already exists)
| Component | Status | Location |
|-----------|--------|----------|
| `_reset_random()` | ✅ Done | `mutations/base.py:282-299` |
| Pass-specific seed | ✅ Done | `_pass_seed = seed + pass_index` |
| Engine seed control | ✅ Done | `core/engine.py:2186-2209` |

### Passes Using Seed
| Pass | Uses `_reset_random()` | Status |
|------|------------------------|--------|
| nop_insertion | ✅ Yes | Line 230 |
| instruction_substitution | ✅ Yes | Line 176 |
| register_substitution | ✅ Yes | Line 414 |
| block_reordering | ❌ No | Needs fix |
| control_flow_flattening | ❌ No | Needs fix |
| dead_code_injection | ❌ No | Needs fix |
| instruction_expansion | ❌ No | Needs fix |
| opaque_predicates | ❌ No | Needs fix |

### Gaps
| Gap | Status | Priority |
|-----|--------|----------|
| CLI seed argument | Partial | High |
| Seed in reports | Missing | High |
| Determinism tests | Missing | High |
| Pass coverage | Partial | Medium |

## Implementation Plan

### Phase 1: Add `_reset_random()` to Missing Passes
Files to update:
- `block_reordering.py`
- `control_flow_flattening.py`
- `dead_code_injection.py`
- `instruction_expansion.py`
- `opaque_predicates.py`

### Phase 2: Seed in Reports and Metadata
- Add `seed` to `MutationRecord`
- Add `seed` to pipeline reports
- Include seed in JSON output

### Phase 3: CLI Seed Documentation
- Document `--seed` argument
- Show seed in output
- Example usage

### Phase 4: Determinism Tests
- Test: same seed → identical output
- Test: different seed → different output
- Test: at least 2 passes

## Acceptance Criteria
- [ ] All mutation passes call `_reset_random()` before random operations
- [ ] Seed appears in CLI output and reports
- [ ] Tests verify deterministic output for fixed seed
- [ ] Tests cover at least 2 mutation passes