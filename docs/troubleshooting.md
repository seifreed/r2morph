# Binary Integrity Troubleshooting Guide

This guide covers common issues when repairing Mach-O and PE binary integrity after mutations, along with solutions and fallback procedures.

## Table of Contents

1. [Mach-O Troubleshooting](#mach-o-troubleshooting)
2. [PE Troubleshooting](#pe-troubleshooting)
3. [Code Signing Issues](#code-signing-issues)
4. [LIEF Fallback Procedures](#lief-fallback-procedures)
5. [Platform-Specific Requirements](#platform-specific-requirements)

---

## Mach-O Troubleshooting

### Common Error: "Not a Mach-O binary"

**Cause:** The file header doesn't match expected Mach-O magic numbers.

**Diagnosis:**
```python
from r2morph.platform.macho_handler import MachOHandler

handler = MachOHandler(path)
print(f"Is Mach-O: {handler.is_macho()}")
print(f"Validate: {handler.validate()}")
```

**Solutions:**
1. Verify the file wasn't corrupted during mutation
2. Check for FAT binary vs thin binary differences
3. Ensure mutations didn't overwrite the header

### Common Error: "Mach-O layout invalid"

**Cause:** LIEF's layout check failed.

**Diagnosis:**
```python
valid, message = handler.validate_integrity()
if not valid:
    print(f"Layout issue: {message}")
```

**Solutions:**
1. Run `handler.fix_load_commands()` to repair load commands
2. Run `handler.fix_segment_permissions()` to verify segments
3. Run `handler.full_repair()` for comprehensive repair

### Common Error: "Mach-O relocations out of segment bounds"

**Cause:** Mutations created relocations pointing outside valid segments.

**Solutions:**
1. Verify mutation didn't shift addresses without updating relocations
2. Check that mutations stayed within segment bounds
3. Use CFG-aware mutations that respect segment boundaries

### Common Error: "Failed to parse Mach-O"

**Cause:** LIEF parsing failed.

**Solutions:**
1. The handler has a fallback parser (`_parse_macho_basic()`)
2. If both fail, the binary may be too corrupted
3. Try repairing the header manually or using `full_repair()`

### FAT Binary Issues

**Error:** Operations fail on FAT (universal) binaries.

**Solutions:**
```python
# Check if FAT
if handler.is_fat_binary():
    # Extract specific architecture
    handler.extract_architecture("x86_64", thin_path)
    
    # Process thin binary
    thin_handler = MachOHandler(thin_path)
    thin_handler.full_repair()
    
    # Re-create FAT binary
    handler.create_fat_binary([thin_path], output_path)
```

---

## PE Troubleshooting

### Common Error: "Not a PE binary"

**Cause:** The file doesn't have a valid DOS stub or PE signature.

**Diagnosis:**
```python
from r2morph.platform.pe_handler import PEHandler

handler = PEHandler(path)
print(f"Is PE: {handler.is_pe()}")
```

**Solutions:**
1. Verify DOS stub starts with "MZ"
2. Check PE signature at e_lfanew offset
3. Ensure mutations didn't corrupt header offsets

### Common Error: "Checksum mismatch"

**Cause:** PE checksum doesn't match calculated value.

**Diagnosis:**
```python
valid, issues = handler.validate_integrity()
for issue in issues:
    if "Checksum" in issue:
        print(f"Checksum issue: {issue}")
```

**Solutions:**
```python
# Fix checksum
if handler.fix_checksum():
    print("Checksum fixed")
else:
    print("Checksum repair failed")
```

### Common Error: "Overlapping sections"

**Cause:** Section virtual addresses overlap.

**Solutions:**
1. Check if mutations modified section boundaries
2. Verify alignment requirements are met
3. Consider rebuilding PE with `refresh_headers()`

### Common Error: "Relocation outside any section"

**Cause:** Relocation addresses don't fall within defined sections.

**Solutions:**
1. Check mutation didn't move code outside sections
2. Verify relocation directory wasn't corrupted
3. Use `handler.get_relocations()` to inspect all relocations

### Common Error: "Missing PE header"

**Cause:** PE optional header is incomplete or missing.

**Solutions:**
1. Run `handler.refresh_headers()` to rebuild headers
2. Check if `handler.is_pe()` returns True
3. Verify file has minimum PE structure

---

## Code Signing Issues

### macOS: "codesign failed"

**Error:** Code signing fails after mutation.

**Diagnosis:**
```python
from r2morph.platform.codesign import CodeSigner

signer = CodeSigner()
if signer.needs_signing(binary_path):
    print("Binary needs signing")
```

**Common Causes:**
1. Binary was modified without re-signing
2. Entitlements file is missing or invalid
3. Hardened runtime requirements not met
4. Code signature was corrupted

**Solutions:**
```python
# Option 1: Ad-hoc signing
signer = CodeSigner()
signer.sign_binary(binary_path, adhoc=True)

# Option 2: With entitlements
signer.sign_binary(
    binary_path,
    adhoc=True,
    entitlements=entitlements_path,
    hardened=True,
)

# Option 3: Remove signature first
signer.remove_signature(binary_path)
signer.sign_binary(binary_path, adhoc=True)
```

### macOS: "signature not valid"

**Error:** `codesign --verify` fails.

**Diagnosis:**
```python
from r2morph.platform.codesign import CodeSigner

signer = CodeSigner()
if not signer.verify(binary_path):
    print("Signature verification failed")
```

**Solutions:**
1. Remove and re-sign:
   ```python
   signer.remove_signature(binary_path)
   signer.sign_binary(binary_path, adhoc=True)
   ```
2. Check for code signature load command issues
3. Verify `__LINKEDIT` segment is intact

### macOS: "hardened runtime" errors

**Error:** Binary fails on hardened runtime.

**Solutions:**
```python
signer.sign_binary(
    binary_path,
    adhoc=True,
    hardened=True,  # Enable hardened runtime
    entitlements=entitlements_path,  # Required entitlements
)
```

### Windows: "signtool not available"

**Error:** signtool.exe not found on PATH.

**Solutions:**
1. Install Windows SDK
2. Add signtool to PATH:
   ```
   set PATH=%PATH%;C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64
   ```
3. Use alternative signing method

### Windows: "Signing failed"

**Error:** signtool sign fails.

**Solutions:**
1. Verify certificate is installed
2. Check certificate thumbprint:
   ```powershell
   certutil -store My
   ```
3. Ensure timestamp server is accessible

---

## LIEF Fallback Procedures

### When LIEF is Not Available

**Symptom:** LIEF import fails.

**Fallback Strategy:**
```python
import logging

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False
    logging.warning("LIEF not available, using fallback parsers")

# Mach-O fallback
handler = MachOHandler(path)
if not HAS_LIEF:
    commands, segments = handler._parse_macho_basic()
    # Use fallback data

# PE fallback
handler = PEHandler(path)
header_info = handler._read_pe_header()
sections = handler.get_sections()  # Has fallback
```

### When LIEF Fails to Parse

**Symptom:** `lief.parse()` returns None or raises.

**Diagnosis:**
```python
try:
    binary = lief.parse(str(path))
    if binary is None:
        print("LIEF returned None - likely corrupted binary")
except Exception as e:
    print(f"LIEF parse error: {e}")
```

**Fallback Actions:**
1. Use manual header parsing (`_read_pe_header()`, `_parse_macho_basic()`)
2. Attempt conservative repair
3. Report the binary as unrepairable

### When LIEF Fails to Write

**Symptom:** `binary.write()` fails.

**Solutions:**
1. Use manual modifications instead
2. Apply binary patches directly
3. For PE: Manually fix checksum
4. For Mach-O: Manually update load commands

---

## Platform-Specific Requirements

### macOS Requirements

| Requirement | Description |
|------------|-------------|
| `codesign` | Required for signing (built-in) |
| `lipo` | Required for FAT binary operations |
| Xcode CLI | `xcode-select --install` |
| Entitlements | Hardened runtime requires entitlements file |

**Setting up:**
```bash
# Install Xcode CLI tools
xcode-select --install

# Verify codesign
codesign --version

# Verify lipo
lipo -info /bin/ls
```

### Windows Requirements

| Requirement | Description |
|------------|-------------|
| `signtool` | Windows SDK (for signing) |
| Certificate | Code signing certificate |
| Timestamp | Timestamp server URL |

**Setting up:**
```powershell
# Verify signtool
signtool /?

# List certificates
certutil -store My

# Test sign (requires certificate)
signtool sign /sha1 <thumbprint> /fd SHA256 binary.exe
```

### Linux Requirements

| Requirement | Description |
|------------|-------------|
| No signing | Linux binaires don't require signing |
| ELF focus | Mach-O/PE handlers still available for analysis |

---

## Error Code Reference

### Mach-O Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| E001 | Invalid magic | Check file format |
| E002 | Missing LC_SEGMENT | Rebuild load commands |
| E003 | Invalid load command | Fix with `fix_load_commands()` |
| E004 | Relocation out of bounds | Check mutations |
| E005 | __LINKEDIT corrupt | May need full rebuild |
| E006 | Signature invalid | Re-sign binary |

### PE Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| E101 | Invalid DOS stub | Check MZ signature |
| E102 | Invalid PE signature | Check PE\x00\x00 |
| E103 | Checksum mismatch | Run `fix_checksum()` |
| E104 | Section overlap | Rebuild sections |
| E105 | Invalid relocation | Run `refresh_headers()` |
| E106 | Import table corrupt | Verify imports |

---

## Best Practices

### Before Mutation

1. Validate input binary integrity
2. Create backup of original
3. Record original checksums

### During Mutation

1. Use CFG-aware mutations
2. Respect segment/section boundaries
3. Track all modifications

### After Mutation

1. Repair integrity (`full_repair()`)
2. Re-sign if needed
3. Validate output binary
4. Test execution

### Recovery Procedure

```python
def safe_mutation_flow(input_path, output_path):
    """Complete mutation flow with error recovery."""
    from pathlib import Path
    import shutil
    from r2morph.platform.macho_handler import MachOHandler
    from r2morph.platform.pe_handler import PEHandler
    from r2morph.platform.codesign import CodeSigner
    
    # 1. Backup original
    backup_path = input_path.with_suffix('.backup')
    shutil.copy(input_path, backup_path)
    
    # 2. Detect format and create handler
    macho_handler = MachOHandler(input_path)
    pe_handler = PEHandler(input_path)
    
    if macho_handler.is_macho():
        handler = macho_handler
        platform = "Darwin"
    elif pe_handler.is_pe():
        handler = pe_handler
        platform = "Windows"
    else:
        # Assume ELF or unknown
        handler = None
        platform = "Linux"
    
    # 3. Validate input
    if handler:
        valid, issues = handler.validate_integrity()
        if not valid:
            print(f"Input has issues: {issues}")
            
    # 4. Apply mutations (placeholder)
    # ... mutation code ...
    
    # 5. Repair integrity
    if handler:
        success, repairs = handler.full_repair()
        print(f"Repairs made: {repairs}")
        
        # 6. Re-sign if needed
        if platform == "Darwin":
            signer = CodeSigner()
            if signer.needs_signing(output_path):
                signer.sign_binary(output_path, adhoc=True)
        
    # 7. Validate output
    if handler:
        output_handler = type(handler)(output_path)
        valid, issues = output_handler.validate_integrity()
        if not valid:
            print(f"Output issues: {issues}")
            # Restore from backup
            shutil.copy(backup_path, output_path)
            return False
            
    # 8. Cleanup
    backup_path.unlink()
    return True
```

---

## Getting Help

If issues persist after following this guide:

1. Check the [GitHub Issues](https://github.com/seifreed/r2morph/issues) for similar problems
2. Enable debug logging:
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```
3. Collect diagnostic information:
   - Binary format (Mach-O/PE/ELF)
   - Architecture (x86_64/ARM64/etc.)
   - Error messages
   - Stack traces
4. Open an issue with the diagnostic information