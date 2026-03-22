# Binary Integrity Repair Enhancement Plan (Issue #4)

## Goal
Strengthen binary integrity repair for Mach-O and PE formats with robust testing and troubleshooting documentation.

## Current State
| Component | Status | File |
|-----------|--------|------|
| Mach-O handler | Implemented | `r2morph/platform/macho_handler.py` |
| PE handler | Implemented | `r2morph/platform/pe_handler.py` |
| Code signer | Implemented | `r2morph/platform/codesign.py` |
| Unit tests | Minimal | Existing tests are basic |
| Integration tests | Missing | No tests with real mutated binaries |
| Troubleshooting docs | Missing | No fallback guides |

## Implementation Plan

### Phase 1: Integration Tests for Mach-O Integrity
**File:** `tests/integration/test_macho_integrity_repair.py`

Tests:
- Test with real Mach-O binaries (system binaries)
- Mutate and repair flow
- Fat binary extraction and reconstruction
- Code signing verification
- Entitlements handling
- Hardened runtime

### Phase 2: Integration Tests for PE Integrity
**File:** `tests/integration/test_pe_integrity_repair.py`

Tests:
- Test with real PE binaries (if available, or synthesized)
- Checksum calculation and verification
- Import/export table integrity
- Relocation directory validation
- Section overlap detection

### Phase 3: Cross-Platform Test Fixtures
**Directory:** `tests/fixtures/platform_binaries/`

- Generate small test binaries for each platform
- Include mutated variants
- Include expected repair outcomes

### Phase 4: Troubleshooting Documentation
**File:** `docs/troubleshooting.md`

Sections:
- Common Mach-O repair failures
- Common PE repair failures
- LIEF fallback procedures
- Code signing failures and solutions
- Platform-specific requirements

### Phase 5: Enhanced Error Handling
**Files:** `r2morph/platform/macho_handler.py`, `r2morph/platform/pe_handler.py`

- Add detailed error codes
- Add recovery suggestions
- Add platform-specific diagnostics

## Acceptance Criteria
- [ ] Tests pass on macOS for Mach-O binaries
- [ ] Tests pass on Windows for PE binaries (where available)
- [ ] Tests pass on Linux for ELF (existing)
- [ ] Documentation covers common failure modes
- [ ] Error messages include actionable suggestions

## Timeline
| Phase | Estimated Time |
|-------|----------------|
| Phase 1: Mach-O tests | 1-2 hours |
| Phase 2: PE tests | 1-2 hours |
| Phase 3: Fixtures | 30 min |
| Phase 4: Documentation | 1 hour |
| Phase 5: Error handling | 30 min |

**Total:** 4-6 hours