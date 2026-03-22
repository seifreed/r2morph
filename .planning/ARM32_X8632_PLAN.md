# ARM32 and x86_32 Support Plan

## Goal
Add complete support for ARM32 (AArch32) and x86_32 (i386) architectures in mutation passes.

## Current State

### Already Implemented
- `dead_code.py`: ARM32/ARM64 and x86_32/x86_64 dead code generation
- `support.py`: `x86` already in prolonged_experimental_architectures
- `assembly.py`: Generic assembly infrastructure

### Gaps Identified
| Module | x86_32 Gap | ARM32 Gap |
|--------|------------|-----------|
| `nop_insertion.py` | No register equivalents | No ARM NOP equivalents |
| `instruction_substitution.py` | No equivalence rules | No ARM rules |
| `register_substitution.py` | Caller-saved defined | No ARM registers |
| `abi_checker.py` | ✅ Defined | ✅ Defined |
| `architecture detection` | 32-bit detection exists | ✅ Working |

## Implementation Plan

### Phase 1: x86_32 NOP Equivalents
Add 32-bit register variants in `nop_insertion.py`:
- Already has 32-bit registers: `eax`, `ebx`, `ecx`, `edx`, `esi`, `edi`
- Need to ensure proper handling in all NOP equivalent templates

### Phase 2: ARM NOP Equivalents
Add ARM-specific NOP equivalents in `nop_insertion.py`:
- `mov r0, r0` (ARM32)
- `mov x0, x0` (ARM64)
- Self-canceling arithmetic sequences

### Phase 3: Architecture-Aware Pass Infrastructure
Update `instruction_substitution.py` and `register_substitution.py`:
- Add x86_32 and ARM32 register lists
- Add architecture-specific equivalence rules

### Phase 4: Tests
- Unit tests for each architecture
- Integration tests with real binaries

## Acceptance Criteria
- [ ] x86_32 NOP insertion works
- [ ] ARM32 NOP insertion works
- [ ] Architecture detection correctly identifies 32-bit variants
- [ ] Tests pass for both architectures
- [ ] Support matrix updated