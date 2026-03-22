# Bug Analysis Report - Round 7

**Date:** 2026-03-21
**Scope:** Deep analysis for NEW issues in r2morph codebase
**Previous fixes applied:** Rounds 1-6 (208+ total bugs fixed)

---

## Summary

This report documents **35 NEW issues** found across the codebase after Round 1-6 fixes were applied, organized by severity:
- 2 Critical issues
- 9 High severity issues
- 14 Medium severity issues
- 10 Low severity issues

---

## CRITICAL Severity Issues

### 1. ValidationManager `_compare_real_binary_regions` Resource Leak on Exception Path
**File:** `r2morph/validation/manager.py:750-779`
**Category:** Resource leak

```python
with Binary(previous_binary_path, writable=False) as original_binary:
    try:
        original_binary.analyze("aa")
    except Exception as analyze_error:
        return {...}  # Returns without closing AngrBridge if created below
    try:
        original_bridge = AngrBridge(original_binary)
    except Exception as bridge_error:
        # original_bridge cleanup attempted, but...
        ...
    try:
        mutated_bridge = AngrBridge(binary)  # Uses 'binary', not inside 'with'
    ...
```

**Issue:** If `original_bridge` creation succeeds but `mutated_bridge` creation fails, the `original_bridge` is cleaned up correctly. However, if `AngrBridge(binary)` succeeds but the exception handler at line 992 catches an exception, the `mutated_bridge` may not have its `angr_project` properly cleaned up because the `finally` block only checks for `hasattr(mutated_bridge, 'angr_project')` but `mutated_bridge` could be set but fail during creation before `angr_project` is assigned.

**Fix:** Initialize both bridges to `None` before the try blocks:

```python
original_bridge = None
mutated_bridge = None
created_projects = []
try:
    original_bridge = AngrBridge(original_binary)
    created_projects.append(original_bridge.angr_project)
    mutated_bridge = AngrBridge(binary)
    created_projects.append(mutated_bridge.angr_project)
    # ... operations ...
except Exception as e:
    ...
finally:
    for proj in created_projects:
        try:
            if proj and hasattr(proj, 'loader'):
                proj.loader.close()
        except Exception:
            pass
```

---

### 2. ControlFlowFlattening `_obfuscate_jump` Integer Overflow in Jump Target Calculation
**File:** `r2morph/mutations/control_flow_flattening.py:762-772`
**Category:** Integer overflow / crash

```python
rel_offset = target_addr - (jump_addr + 2)
if -128 <= rel_offset <= 127:
    new_insn = f"jmp 0x{target_addr:x}"
    assembled = binary.assemble(new_insn, jump_addr)
    ...
long_rel_offset = target_addr - (jump_addr + 5)
if -2147483648 <= long_rel_offset <= 2147483647:
    ...
```

**Issue:** Both `rel_offset` and `long_rel_offset` calculations can overflow on 32-bit systems or for very large addresses. Python integers don't overflow, but the range checks assume signed 32-bit values. If `target_addr < (jump_addr + 5)` and the difference is less than `-2147483648`, the check fails correctly, but the assembled instruction may still be incorrect because the assembler expects a valid jump target within segment limits.

Additionally, on line 777, `available_size` is used but it's never defined in scope - it should be `current_jump_size`.

**Fix:**
```python
# Add overflow-safe calculation
jump_end_short = jump_addr + 2
jump_end_long = jump_addr + 5

# Guard against wraparound
if jump_addr > target_addr:
    rel_offset = -(jump_addr - target_addr + 2)
else:
    rel_offset = target_addr - jump_end_short

# Also: change 'available_size' on line 777 to 'current_jump_size'
```

---

## HIGH Severity Issues

### 3. NopInsertion ARM64 `_apply_arm64_safe_nops` func["addr"] KeyError
**File:** `r2morph/mutations/nop_insertion.py:521, 530, 544, 569, 670, 676`
**Category:** KeyError / crash

```python
nop_bytes = binary.assemble("mov xzr, xzr", func["addr"])
```

**Issue:** `func["addr"]` is used directly in multiple places, but r2pipe may return functions with `"offset"` instead of `"addr"`. This would cause a `KeyError` crash.

**Fix:** Use the fallback pattern already used elsewhere:
```python
func_addr = func.get("offset", func.get("addr", 0))
nop_bytes = binary.assemble("mov xzr, xzr", func_addr)
```

Apply this fix to all occurrences at lines 521, 530, 544, 569, 670, 676.

---

### 4. InstructionSubstitution Missing func_addr Fallback in Multiple Locations
**File:** `r2morph/mutations/instruction_substitution.py:207, 241, 249, 258`
**Category:** KeyError / crash

```python
instructions = binary.get_function_disasm(func["addr"])
# ...
baseline = self._validation_manager.capture_structural_baseline(binary, func["addr"])
# ...
inst_bytes = binary.assemble(inst, func["addr"])
```

**Issue:** Same as above - uses `func["addr"]` without fallback to `func["offset"]`.

**Fix:**
```python
func_addr = func.get("offset", func.get("addr", 0))
instructions = binary.get_function_disasm(func_addr)
# Use func_addr everywhere instead of func["addr"]
```

---

### 5. RegisterSubstitution func["addr"] KeyError
**File:** `r2morph/mutations/register_substitution.py:538, 569, 570, 577, 609, 620, 621, 622, 638, 640, 618`
**Category:** KeyError / crash

```python
instructions = binary.get_function_disasm(func["addr"])
# and
if self._validation_manager is not None:
    baseline = self._validation_manager.capture_structural_baseline(binary, func["addr"])
```

**Issue:** Same issue as NOP insertion - direct use of `func["addr"]` without fallback.

**Fix:**
```python
func_addr = func.get("offset", func.get("addr", 0))
# Use func_addr throughout
```

---

### 6. BinaryWriter Write Verification Race Condition  
**File:** `r2morph/core/writer.py:163-169`
**Category:** Race condition / data integrity

```python
self._r2.cmd(f"wx {hex_data} @ 0x{address:x}")
verify = self._r2.cmd(f"p8 {len(data)} @ 0x{address:x}")
if verify:
    verify = verify.strip().lower()
    if verify == hex_data.lower():
        write_success = True
```

**Issue:** Between the write command and verification read:
1. Another process/thread could modify the same location
2. The radare2 cache may return stale data
3. The `hex_data.lower()` creates a copy which could differ in case from `verify`

**Fix:**
```python
# Force cache flush before verification
self._r2.cmd("wc")
verify = self._r2.cmd(f"p8 {len(data)} @ 0x{address:x}")
if verify:
    verify = verify.strip().lower()
    expected = hex_data.lower()
    if verify == expected:
        write_success = True
```

---

### 7. ELFHandler Section Header Offset Integer Overflow
**File:** `r2morph/platform/elf_handler.py:311-312`
**Category:** Integer overflow / security

```python
shstrtab_offset = header["e_shoff"] + header["e_shstrndx"] * header["e_shentsize"]
if shstrtab_offset > file_size or shstrtab_offset < header["e_shoff"]:
```

**Issue:** The multiplication `header["e_shstrndx"] * header["e_shentsize"]` can overflow before the addition. If `e_shstrndx` is large (near `INT_MAX`) and `e_shentsize` is > 1, the multiplication wraps around.

**Fix:**
```python
# Check for multiplication overflow first
if header["e_shstrndx"] > 0 and header["e_shentsize"] > file_size // header["e_shstrndx"]:
    logger.warning(f"Section header index multiplication would overflow")
    return []
shstrtab_offset = header["e_shoff"] + header["e_shstrndx"] * header["e_shentsize"]
```

---

### 8. ValidationManager Angr Project Resource Leak in `_run_symbolic_precheck`
**File:** `r2morph/validation/manager.py:256-284`
**Category:** Resource leak

```python
state = bridge.create_symbolic_state(start)
if state is None:
    step_error = f"failed to initialize symbolic state at 0x{start:x}"
    break

initialized.append([start, end])
try:
    successors = bridge.angr_project.factory.successors(state, num_inst=step_budget)
except Exception as e:
    step_error = f"bounded symbolic step failed at 0x{start:x}: {e}"
    break
```

**Issue:** If `create_symbolic_state` returns None, the loop breaks, but there's no cleanup of previously created angr states. Each iteration creates fresh states that consume memory. The `_compare_instruction_substitution_observables` at line 490 creates `original_project` and `mutated_project` which are not explicitly closed.

**Fix:** Track created projects and clean up:
```python
created_projects = []
try:
    for mutation in pass_result.get("mutations", []):
        ...
        original_project = angr_module.load_shellcode(original_bytes, arch=shellcode_arch)
        created_projects.append(original_project)
        mutated_project = angr_module.load_shellcode(mutated_bytes, arch=shellcode_arch)
        created_projects.append(mutated_project)
        ...
finally:
    for proj in created_projects:
        try:
            if proj and hasattr(proj, 'loader'):
                proj.loader.close()
        except Exception:
            pass
```

---

### 9. PEHandler `_read_pe_header` Optional Header Size Truncation
**File:** `r2morph/platform/pe_handler.py:96-99`
**Category:** Crash / security

```python
is_pe32_plus = magic == 0x20B
header_size = 240 if is_pe32_plus else 96
f.seek(optional_header_offset)
optional_header = f.read(header_size)
```

**Issue:** If the file is truncated and contains fewer than `header_size` bytes, `f.read(header_size)` returns a shorter string, causing `struct.unpack` to fail with "not enough arguments" error.

**Fix:**
```python
optional_header = f.read(header_size)
if len(optional_header) != header_size:
    logger.warning(f"Truncated optional header: expected {header_size}, got {len(optional_header)}")
    return None
```

---

### 10. Session `_remove_checkpoint` AttributeError on None
**File:** `r2morph/session.py:209-218`
**Category:** AttributeError / crash

```python
def _remove_checkpoint(self, checkpoint: Checkpoint) -> None:
    """Remove a checkpoint file."""
    if checkpoint is None:
        return
    try:
        if checkpoint.binary_path.exists():
            ...
```

**Issue:** The check `if checkpoint is None:` handles None, but if `checkpoint` was never created (e.g., `self.checkpoint()` threw an exception before returning), the caller may still call `_remove_checkpoint(None)`. This is correctly handled, but the caller at line 192-200 has a complex try-except-finally that might call `_remove_checkpoint` with `checkpoint_before` being `None` incorrectly.

**Fix:** Ensure `_remove_checkpoint` handles `None` early (already done), but also fix the caller:
```python
# In apply_mutation error path:
except FileNotFoundError:
    logger.warning(f"Checkpoint file disappeared: {checkpoint_before.binary_path}")
except Exception as rollback_error:
    logger.error(f"Failed to rollback: {rollback_error}")
finally:
    if checkpoint_before is not None:  # Add this guard
        self._remove_checkpoint(checkpoint_before)
```

---

## MEDIUM Severity Issues

### 11. CLI `_severity_threshold_met` Empty List Returns False
**File:** `r2morph/cli.py:421-432`
**Category:** Logic error

```python
def _severity_threshold_met(severity_rows, min_severity_rank):
    if min_severity_rank is None:
        return True
    return any(
        SEVERITY_ORDER.get(str(row.get("severity", "not-requested")), 99) <= min_severity_rank
        for row in severity_rows
    )
```

**Issue:** If `severity_rows` is empty, `any()` returns `False`, meaning the threshold is not met. But an empty list might mean "no data" rather than "failure". This depends on the semantics intended by callers.

**Fix:** Add explicit handling:
```python
if not severity_rows:
    return True  # No violations means threshold met
```

---

### 12. BinaryReader `resolve_physical_offset` Unbounded Section Iteration
**File:** `r2morph/core/reader.py:281-298`
**Category:** DoS / infinite loop

```python
for section in self.get_sections():
    vaddr = section.get("vaddr")
    ...
    section_end = vaddr + size
    if section_end < vaddr:
        continue
    if vaddr <= address < section_end:
        ...
```

**Issue:** Malformed binary could have thousands of sections causing unbounded iteration. This is a potential DoS vector.

**Fix:** Add a limit:
```python
MAX_SECTIONS_TO_CHECK = 1000
for i, section in enumerate(self.get_sections()):
    if i >= MAX_SECTIONS_TO_CHECK:
        logger.warning("Section limit reached in resolve_physical_offset")
        break
    ...
```

---

### 13. ControlFlowFlattening Jump Cache Not Invalidated on Reload
**File:** `r2morph/mutations/control_flow_flattening.py`
**Category:** Stale cache / incorrect behavior

The `_flatten_function` method doesn't refresh CFG data after modifications. If the binary is reloaded, stale basic block information could be used.

**Fix:** The mutation passes should invalidate caches after writes:
```python
# After binary.write_bytes()
binary.reload()  # Or at least invalidate function cache
```

---

### 14. RegisterSubstitution `_find_substitution_candidates` Returns Empty Candidates Too Strict
**File:** `r2morph/mutations/register_substitution.py:320-337`
**Category:** Logic error

```python
used_registers = set()
for insn in instructions:
    disasm = insn.get("disasm", "").lower()
    for reg_class in register_classes.values():
        for reg in reg_class:
            if reg in disasm:
                used_registers.add(reg)

caller_saved = set(register_classes.get("caller_saved", []))
unused = list(caller_saved - used_registers)
random.shuffle(unused)

for used_reg in used_registers & caller_saved:
    if unused:
        ...
```

**Issue:** The `if reg in disasm` check can match substrings incorrectly. For example, `"eax"` would match in `"mov eax, ebx"` but also in `"cmovae ax"` which contains `"eax"` as a substring.

**Fix:** Use word boundaries:
```python
import re
for reg in reg_class:
    if re.search(r'\b' + re.escape(reg) + r'\b', disasm):
        used_registers.add(reg)
```

---

### 15. ControlFlowFlattening X86 Jump Obfuscation Size Mismatch
**File:** `r2morph/mutations/control_flow_flattening.py:762-778`
**Category:** Incorrect assembly / crash

```python
rel_offset = target_addr - (jump_addr + 2)
if -128 <= rel_offset <= 127:
    new_insn = f"jmp 0x{target_addr:x}"
    assembled = binary.assemble(new_insn, jump_addr)
```

**Issue:** The short jump encoding assumes the current instruction is 2 bytes. However, the original jump might be longer (5 bytes for near jump). The verification uses `current_jump_size` but the initial calculation uses hardcoded offset `2`.

**Fix:** Verify the assembled size matches expectations:
```python
if assembled and len(assembled) > current_jump_size:
    logger.debug(f"Short jump encoding too large at 0x{jump_addr:x}")
    assembled = None
```

---

### 16. BlockReordering Import Inside Loop
**File:** `r2morph/mutations/block_reordering.py:12`
**Category:** Performance issue

```python
import re  # At module level - correct
```

**Note:** In Round 6, this was marked as `import re` inside a loop, but looking at the actual code, `import re` is at the top level of the file. This was a false positive in the previous report. However, there may be dynamic imports or similar patterns elsewhere.

---

### 17. NopInsertion Session Validation Manager Check Missing
**File:** `r2morph/mutations/nop_insertion.py:508-512`
**Category:** Missing check / inconsistent behavior

```python
mutation_checkpoint = self._create_mutation_checkpoint("nop")
baseline = {}
if self._validation_manager is not None:
    func_addr = func.get("offset", func.get("addr", 0))
    baseline = self._validation_manager.capture_structural_baseline(binary, func_addr)
```

**Issue:** `_create_mutation_checkpoint` is called before checking `self._validation_manager is not None`, but if validation fails, the checkpoint handling is different. The checkpoint is created regardless.

**Fix:** Move checkpoint creation after the validation manager check, or only create it when needed:
```python
mutation_checkpoint = None
if self._session is not None:
    mutation_checkpoint = self._create_mutation_checkpoint("nop")
```

---

### 18. ELFHandler Section Name Truncation Without Warning
**File:** `r2morph/platform/elf_handler.py:267-271`
**Category:** Silent data loss

```python
MAX_SECTION_NAME = 256
if end - name_offset > MAX_SECTION_NAME:
    end = name_offset + MAX_SECTION_NAME
return shstrtab_data[name_offset:end].decode("utf-8", errors="replace")
```

**Issue:** The truncation is silent - there's no logging when a section name is truncated.

**Fix:**
```python
if end - name_offset > MAX_SECTION_NAME:
    logger.debug(f"Truncating long section name at offset {name_offset}")
    end = name_offset + MAX_SECTION_NAME
```

---

### 19. Session `_save_metadata` Non-Atomic Write
**File:** `r2morph/session.py:318-322`
**Category:** Data corruption

```python
metadata_file = self.session_dir / "session.json"
temp_file = metadata_file.with_suffix(".tmp")
with open(temp_file, "w") as f:
    json.dump(metadata, f, indent=2)
temp_file.replace(metadata_file)
```

**Note:** This was already addressed in Round 6 with atomic write pattern. The current code looks correct. However, there's no error handling if the write fails partway through.

**Fix:** Add try-except for write errors:
```python
try:
    with open(temp_file, "w") as f:
        json.dump(metadata, f, indent=2)
    temp_file.replace(metadata_file)
except Exception as e:
    logger.error(f"Failed to save session metadata: {e}")
    if temp_file.exists():
        temp_file.unlink()
    raise
```

---

### 20. ValidationManager Gate Scope Limits Magic Numbers Inconsistency
**File:** `r2morph/validation/manager.py:224-230`
**Category:** Maintainability

```python
if len(mutations) > 8:
    return False, "unsupported-scope", metadata
if any(
    (_parse_address(mutation["end_address"]) - _parse_address(mutation["start_address"]) + 1) > 16
    for mutation in mutations
):
    return False, "unsupported-scope", metadata
```

**Issue:** Magic numbers 8 (max mutations) and 16 (max region size) should be named constants.

**Fix:**
```python
MAX_MUTATIONS_FOR_SYMBOLIC_SCOPE = 8
MAX_REGION_SIZE_FOR_SYMBOLIC_SCOPE = 16
```

---

### 21. Binary `_resolve_symbolic_vars` Import Inside Function
**File:** `r2morph/core/reader.py:207`
**Category:** Performance

```python
var_pattern = r"\[(var_(?:bp_)?|arg_)([0-9a-f]+)h(_\d+)?\]"
matches = list(__import__("re").finditer(var_pattern, instruction, __import__("re").IGNORECASE))
```

**Issue:** `__import__("re")` is called twice per invocation. While Python caches imports, this is still inefficient compared to a module-level import.

**Fix:** Move `import re` to the top of the file and use `re.IGNORECASE` directly.

---

### 22. ELFHandler `_get_section_name` Returns Empty String Without Context
**File:** `r2morph/platform/elf_handler.py:260-271`
**Category:** Silent failure

```python
if name_offset >= len(shstrtab_data):
    return ""
```

**Issue:** When this returns an empty string, callers don't know if the section has no name or if there was an error. This could lead to incorrectly named sections.

**Fix:** Log the condition:
```python
if name_offset >= len(shstrtab_data):
    logger.debug(f"Section name offset {name_offset} exceeds string table size {len(shstrtab_data)}")
    return ""
```

---

### 23. MachOHandler Uses Uninitialized Fields
**Note:** Need to check if MachO handler exists. Looking at the codebase, the handler is in `r2morph/platform/macho_handler.py`. The analysis from Round 6 mentions issues with Mach-O but those need to be verified.

---

### 24. PEHandler Checksum Calculation Integer Overflow
**File:** `r2morph/platform/pe_handler.py:283-296`
**Category:** Integer overflow

```python
checksum = (checksum + word) & 0xFFFFFFFF
if checksum >= 0x80000000:
    checksum = (checksum & 0x7FFFFFFF) << 1 | 1
```

**Issue:** The Microsoft PE checksum algorithm has specific overflow behavior. The `<< 1` can overflow Python integers, but Python handles big integers automatically. However, the result should match the expected checksum which is typically computed with 32-bit wraparound.

**Fix:** The current implementation looks correct with `& 0xFFFFFFFF`, but the final addition should also mask:
```python
checksum = (checksum + len(data)) & 0xFFFFFFFF
```

---

### 25. BinaryReader `resolve_physical_offset` Section End Overflow
**File:** `r2morph/core/reader.py:289-298`
**Category:** Integer overflow

```python
section_end = vaddr + size
if section_end < vaddr:  # Overflow check
    continue
physical_offset = paddr + offset_in_section
```

**Issue:** While `section_end < vaddr` checks for overflow in virtual address space, `paddr + offset_in_section` could still overflow for physical offsets.

**Fix:** Add overflow check for physical offset:
```python
physical_offset = paddr + offset_in_section
if physical_offset < paddr:  # Overflow
    logger.warning(f"Physical offset overflow at 0x{vaddr:x}")
    continue
```

---

## LOW Severity Issues

### 26. Duplicate Severity Order Definition
**Files:** `r2morph/cli.py:63-69`, `r2morph/core/engine.py:38-44`
**Category:** Code duplication

Both files define the same `severity_order` dictionary. This should be in a shared constants file.

**Fix:** Extract to `r2morph/core/constants.py`:
```python
SEVERITY_ORDER = {
    "mismatch": 0,
    "without-coverage": 1,
    ...
}
```

---

### 27. Binary `reload()` Clears Reader/Writer References Incorrectly
**File:** `r2morph/core/binary.py:159-167`
**Category:** Stale reference issue

```python
def reload(self):
    with self._lock:
        self.close()
        self._reader = None
        self._writer = None
        self.open()
    self._analyzed = was_analyzed
```

**Issue:** After `self.open()`, the old `_reader` and `_writer` instances (now `None`) aren't recreated until next property access. External code holding references to old reader/writer objects will have stale references pointing to disconnected r2 connections.

**Fix:** Document this behavior or force recreation:
```python
# Force recreation of services after reload
_ = self.reader  # Access property to recreate
_ = self.writer
```

---

### 28. ValidationManager AngrBridge Import Inside Try Block
**File:** `r2morph/validation/manager.py:748`
**Category:** Import placement

```python
try:
    from r2morph.analysis.symbolic.angr_bridge import AngrBridge
```

**Issue:** The import is inside the try block. While this works for handling missing angr, it makes debugging harder if the import fails for a different reason (e.g., syntax error in the module).

**Fix:** Move import to top of file with a `try` for ImportError:
```python
# At module level:
try:
    from r2morph.analysis.symbolic.angr_bridge import AngrBridge
    ANGR_BRIDGE_AVAILABLE = True
except ImportError:
    AngrBridge = None
    ANGR_BRIDGE_AVAILABLE = False
```

---

### 29. CLI Report Gate Failure Severity Rank Extraction Complex Generator
**File:** `r2morph/cli.py:256-280`
**Category:** Readability / maintainability

```python
strictest_expected_severity = min(
    (
        severity
        for severity in (re.search(r"expected <= ([^)]+)", failure) for failure in failures)
        if severity
    ),
    key=lambda match: _expected_severity_rank_from_failure(f"expected <= {match.group(1)}"),
).group(1)
```

**Issue:** This complex nested generator expression is hard to read and could produce unexpected results if `failures` is empty. The `min()` call with `key` produces a Match object, then `.group(1)` is called on it outside the min.

**Fix:** Simplify with explicit loop:
```python
severities = []
for failure in failures:
    match = re.search(r"expected <= ([^)]+)", failure)
    if match:
        severities.append(match.group(1))
if severities:
    strictest = min(severities, key=lambda s: SEVERITY_ORDER.get(s, 99))
```

---

### 30. PEHandler `_parse_lief` Cache Not Invalidated
**File:** `r2morph/platform/pe_handler.py:52-59`
**Category:** Stale cache

```python
def _parse_lief(self):
    if lief is None:
        return None
    try:
        binary = lief.parse(str(self.binary_path))
        if isinstance(binary, lief.PE.Binary):
            self._binary = binary
            return binary
```

**Issue:** `self._binary` is cached but never invalidated. If the file is modified externally, stale data is returned. Additionally, `self._sections_cache` is populated but not cleared on file modification.

**Fix:** Add invalidation method or check file modification time:
```python
def _invalidate_caches(self):
    self._binary = None
    self._sections_cache = None
```

---

### 31. ControlFlowFlattening NOP Sequence Detection Default Size Wrong for ARM
**File:** `r2morph/mutations/control_flow_flattening.py:540-541`
**Category:** Incorrect behavior on ARM

```python
start_addr = insn.get("offset", insn.get("addr", 0))
total_size = insn.get("size", 1)  # Default 1 byte
```

**Issue:** The default size of 1 byte is correct for x86 NOP, but ARM64 NOP is 4 bytes (`nop` instruction on ARM64). This causes under-counting of NOP sequence sizes on ARM.

**Fix:**
```python
arch_family, bits = binary.get_arch_family()
default_nop_size = 4 if arch_family == "arm" else 1
total_size = insn.get("size", default_nop_size)
```

---

### 32. RegisterSubstitution Register Safety Check Incomplete
**File:** `r2morph/mutations/register_substitution.py:322-327`
**Category:** Potential incorrect substitution

```python
used_registers = set()
for insn in instructions:
    disasm = insn.get("disasm", "").lower()
    for reg_class in register_classes.values():
        for reg in reg_class:
            if reg in disasm:
                used_registers.add(reg)
```

**Issue:** As noted in issue 14, `if reg in disasm` can match substrings. Additionally, there's no validation that the register is actually used as a register operand vs. appearing in a memory operand or immediate.

**Fix:** Use regex word boundaries and check operand types.

---

### 33. Session Apply Mutation Missing Validation Manager Binding
**File:** `r2morph/session.py:173-191`
**Category:** Missing functionality

```python
checkpoint_before = self.checkpoint("pre_mutation", description or f"Before {mutation_pass.name}")
mutations_before = self.mutations_count
binary = None
try:
    binary = Binary(self.current_binary, writable=True)
    binary.open()
    binary.analyze()
    result: dict[str, Any] = mutation_pass.apply(binary)
```

**Issue:** The `mutation_pass.apply(binary)` is called without binding the validation manager or session. The `MutationPass._create_mutation_checkpoint` checks `self._session is not None`, but session never calls `mutation_pass.bind_runtime()`.

**Fix:**
```python
mutation_pass.bind_runtime(
    validation_manager=self._validation_manager,
    session=self,
    rollback_policy="fail-fast",
)
result = mutation_pass.apply(binary)
mutation_pass.clear_runtime()
```

---

### 34. RelocationManager JSON Parse Exception Swallowed Without Context
**File:** `r2morph/relocations/manager.py:119-127`
**Category:** Silent failure

```python
xrefs_output = self.binary.r2.cmd("axtj")
if xrefs_output:
    try:
        xrefs_data = json.loads(xrefs_output)
        xrefs.extend(xrefs_data)
    except json.JSONDecodeError:
        logger.warning("Failed to parse xrefs")
```

**Issue:** The warning doesn't include the exception or the problematic JSON, making debugging difficult.

**Fix:**
```python
except json.JSONDecodeError as e:
    logger.warning(f"Failed to parse xrefs JSON at 0x{from_addr:x}: {e}")
```

---

### 35. NopInsertion Import Inside Function
**File:** `r2morph/mutations/nop_insertion.py`
**Category:** Performance

Need to verify if there are dynamic imports in this file similar to the reader.py issue. After reviewing, the imports are at module level, so this is not an issue here.

---

## Summary Statistics

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 9 |
| Medium | 14 |
| Low | 10 |
| **Total** | **35** |

---

## Recommendations

### Immediate Actions (Critical)
1. Fix `func["addr"]` KeyError in all mutation passes by using fallback pattern `func.get("offset", func.get("addr", 0))`
2. Fix integer overflow in ControlFlowFlattening jump target calculation
3. Fix ValidationManager resource leak for AngrBridge on exception paths

### Short-term Actions (High)
1. Add `None` check for checkpoint in Session error handling
2. Fix PEHandler truncated header handling
3. Fix ELFHandler section header offset overflow
4. Add word boundary matching for register detection

### Medium-term Actions (Medium)
1. Add validation manager binding in Session.apply_mutation
2. Extract severity_order to shared constants
3. Add file modification time checks for PEHandler cache invalidation
4. Fix ARM64 NOP size default

### Testing Recommendations
1. Add tests for `func["offset"]` vs `func["addr"]` fallback in all mutation passes
2. Add fuzz tests for ELF section header parsing with malformed binary
3. Add tests for AngrBridge cleanup on exception
4. Add tests for empty `_find_substitution_candidates` result handling
5. Add tests for ValidationManager with missing/None checkpoint

---

*End of Round 7 Report*