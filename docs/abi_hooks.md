# ABI Hooks for Mutation Passes

This document describes how to integrate ABI (Application Binary Interface) invariant checking into mutation passes.

## Overview

ABI hooks ensure that mutations preserve platform-specific calling conventions and requirements:

- **Stack alignment** (16-byte for x86_64)
- **Red zone** (128 bytes below RSP for x86_64 SysV)
- **Shadow space** (32 bytes for Windows x64)
- **Callee-saved registers** (platform-specific)

## Supported Platforms

| Platform | ABI | Stack Alignment | Red Zone | Shadow Space |
|----------|-----|-----------------|----------|--------------|
| Linux x86_64 | System V | 16-byte | 128 bytes | - |
| Windows x64 | Microsoft | 16-byte | - | 32 bytes |
| Linux ARM64 | AAPCS64 | 16-byte | - | - |
| Linux ARM32 | AAPCS | 8-byte | - | - |

## Quick Start

### Using ABI Hook in a Mutation Pass

```python
from r2morph.mutations.abi_hook import ABIMutationHook, ABIViolationAction
from r2morph.core.binary import Binary

def run_mutation(binary: Binary):
    # Create hook
    hook = ABIMutationHook(binary, action=ABIViolationAction.WARN)
    
    for func in binary.get_functions():
        addr = func.get("offset", 0)
        
        # Snapshot ABI state before mutation
        snapshot = hook.snapshot_function(addr)
        
        # ... apply mutations ...
        
        # Validate after mutation
        result = hook.validate_function(addr)
        
        if not result.valid:
            print(f"ABI violations in function 0x{addr:x}")
            for v in result.new_violations:
                print(f"  {v.violation_type.value}: {v.description}")
```

### Creating an ABI-Aware Pass

```python
from r2morph.mutations.abi_aware_base import ABIAwareMutationPass
from r2morph.core.binary import Binary

class MyMutationPass(ABIAwareMutationPass):
    def __init__(self):
        super().__init__(
            name="my_mutation",
            enforce_abi=True,
            abi_action="warn",  # or "block", "skip"
        )
    
    def apply_abi_aware(self, binary, abi_hook):
        for func in binary.get_functions():
            addr = func.get("offset", 0)
            
            # Snapshot ABI
            if abi_hook:
                abi_hook.snapshot_function(addr)
            
            # Apply mutations
            # ...
            
            # Validate ABI
            if abi_hook:
                result = abi_hook.validate_function(addr)
                if not result.valid:
                    # Handle violation
                    pass
```

## Configuration Options

### ABIMutationHook

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `action` | ABIViolationAction | WARN | What to do on violation |
| `check_stack_alignment` | bool | True | Check stack alignment |
| `check_callee_saved` | bool | True | Check callee-saved registers |
| `check_red_zone` | bool | True | Check red zone usage |
| `check_shadow_space` | bool | True | Check shadow space (Windows) |

### ABIViolationAction

| Action | Behavior |
|--------|----------|
| `WARN` | Log violations, continue execution |
| `BLOCK` | Prevent saving binaries with violations |
| `SKIP` | Skip mutation on functions with violations |

## Violation Types

### Stack Alignment

Detected when `call` instruction occurs with misaligned stack.

**x86_64 System V / Windows:**
- Stack must be 16-byte aligned before CALL
- Violation: `stack_delta % 16 != 0`

**ARM64:**
- Stack must be 16-byte aligned at function boundaries

### Red Zone Clobber

Detected when mutation exceeds red zone in leaf functions.

**x86_64 System V only:**
- 128 bytes below RSP
- Only for leaf functions (no CALL instructions)

### Shadow Space Violation

Detected when Windows x64 shadow space requirements not met.

**Windows x64:**
- 32 bytes (4 pointers) must be allocated before CALL
- Caller must provide space for 4 register arguments

### Callee-Saved Register Clobber

Detected when callee-saved registers are modified without save/restore.

**x86_64 System V:** `rbx, r12-r15, rbp`
**Windows x64:** `rbx, rdi, rsi, r12-r15, rbp`
**ARM64:** `x19-x30`

## API Reference

### ABIMutationHook

```python
class ABIMutationHook:
    def __init__(self, binary, action=WARN, **checks): ...
    
    def snapshot_function(self, address) -> ABISnapshot: ...
    def validate_function(self, address, regions=None) -> ABICheckResult: ...
    def validate_region(self, start, end) -> ABICheckResult: ...
    def should_skip_mutation(self, address) -> bool: ...
    def can_save_binary(self) -> bool: ...
    def get_diagnostics(self) -> dict: ...
    def reset(self): ...
```

### ABISnapshot

```python
@dataclass
class ABISnapshot:
    function_address: int
    violations: list[ABIViolation]
    stack_alignment_ok: bool
    callee_saved_ok: bool
    red_zone_ok: bool
    shadow_space_ok: bool
```

### ABICheckResult

```python
@dataclass
class ABICheckResult:
    valid: bool
    violations: list[ABIViolation]
    new_violations: list[ABIViolation]
    check_types: list[str]
```

### Factory Function

```python
def create_abi_hook(binary, strict=False, checks=None) -> ABIMutationHook:
    """Create an ABI hook with common configurations."""
```

## Examples

### Strict Mode (Block on Violation)

```python
hook = ABIMutationHook(binary, action=ABIViolationAction.BLOCK)

# ... mutations ...

if not hook.can_save_binary():
    print("Cannot save binary: ABI violations detected")
    diagnostics = hook.get_diagnostics()
    for v in diagnostics["violations"]:
        print(f"  {v['type']} at {v['location']}: {v['description']}")
    return

binary.save(output_path)
```

### Skip Mode (Skip Functions with Violations)

```python
hook = ABIMutationHook(binary, action=ABIViolationAction.SKIP)

for func in binary.get_functions():
    addr = func.get("offset", 0)
    
    if hook.should_skip_mutation(addr):
        print(f"Skipping function 0x{addr:x} due to ABI issues")
        continue
    
    # Apply mutations safely
```

### Selective Checks

```python
# Only check stack alignment
hook = ABIMutationHook(
    binary,
    check_stack_alignment=True,
    check_callee_saved=False,
    check_red_zone=False,
    check_shadow_space=False,
)

# Only check callee-saved registers
hook = ABIMutationHook(
    binary,
    check_stack_alignment=False,
    check_callee_saved=True,
    check_red_zone=False,
    check_shadow_space=False,
)
```

### Platform-Specific Handling

```python
from r2morph.analysis.abi_checker import detect_abi

abi_spec = detect_abi(binary)

if abi_spec.abi_type == ABIType.X86_64_WINDOWS:
    # Windows-specific: Check shadow space
    hook = ABIMutationHook(
        binary,
        check_shadow_space=True,
        check_red_zone=False,  # No red zone on Windows
    )
elif abi_spec.abi_type == ABIType.X86_64_SYSTEM_V:
    # Linux/macOS: Check red zone
    hook = ABIMutationHook(
        binary,
        check_red_zone=True,
        check_shadow_space=False,  # No shadow space on Linux
    )
```

## Best Practices

1. **Always snapshot before mutation**: Call `snapshot_function()` before any mutation
2. **Validate after mutation**: Call `validate_function()` after mutations complete
3. **Use BLOCK in production**: Prevent broken binaries from being saved
4. **Use WARN in development**: Identify issues without blocking
5. **Handle all violation types**: Don't ignore any category
6. **Document ABI requirements**: Note which checks are enabled for each pass

## Adding ABI Checks to New Passes

```python
from r2morph.mutations.abi_aware_base import ABIAwareMutationPass
from r2morph.mutations.abi_hook import ABIViolationAction

class NewMutationPass(ABIAwareMutationPass):
    def __init__(self):
        super().__init__(
            name="new_mutation",
            enforce_abi=True,
            abi_action="block",  # Strict in production
            abi_checks=["stack_alignment", "callee_saved"],
        )
    
    def apply_abi_aware(self, binary, abi_hook):
        for func in binary.get_functions():
            addr = func.get("offset", 0)
            
            # ABI hook is automatically managed by base class
            self.apply_to_function(binary, addr)
        
        return {"mutations_applied": len(self._records)}
    
    def apply_to_function_abi_aware(self, binary, addr, abi_snapshot):
        # Apply mutation to function
        # ABI is already snapshotted
        
        # Check if we can continue
        if not self.can_continue_after_abi_check(addr):
            return None
        
        # ... apply mutations ...
        
        # Validate ABI after mutation
        result = self.validate_abi(addr, mutation_regions=[(start, end)])
        
        if not result.valid:
            # Handle violation
            pass
        
        return {"mutations_applied": count}
```

## Troubleshooting

### Stack Alignment Violations

**Cause:** Function prologue/epilogue incorrect or mutations changed stack offset.

**Solution:**
1. Check `push`/`pop` pairs
2. Verify `sub rsp, N` where N is multiple of 16
3. Use `abi_hook.snapshot_function()` before and `validate_function()` after

### Callee-Saved Register Violations

**Cause:** Mutation modified callee-saved register without save/restore.

**Solution:**
1. Push/pop callee-saved registers around mutation
2. Or use caller-saved registers (rax, rcx, rdx, r8-r11 on x86_64)
3. For ARM64, use x0-x18 (caller-saved)

### Red Zone Violations

**Cause:** Mutation inserted code that exceeds 128 bytes in leaf function.

**Solution:**
1. Check if function has CALL instructions
2. For leaf functions, keep mutations under 128 bytes
3. Or adjust stack pointer before mutation

### Shadow Space Violations

**Cause:** Windows x64 CALL without proper shadow space allocation.

**Solution:**
```asm
; Before:
call func

; After:
sub rsp, 32  ; Allocate shadow space
call func
add rsp, 32  ; Clean up
```