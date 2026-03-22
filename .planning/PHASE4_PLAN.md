# Phase 4 Implementation Plan: UX & Integration

**Status:** Pending
**Priority:** P3 (Low)
**Estimated Duration:** 6-9 weeks

---

## Overview

Phase 4 focuses on user experience and integration:
- **Interactive TUI** - Terminal User Interface for mutation selection
- **SARIF 2.1.0 Output** - Standard format for CI/CD integration
- **Analysis Cache** - Persist analysis results for faster repeated runs

---

## 4.1 Interactive TUI

### Goal
Provide an interactive terminal interface for:
- Mutation preview before application
- Function selection
- Pass selection with descriptions
- Manual confirmation workflow

### Files to Create

```
r2morph/cli/tui.py                    # Main TUI implementation
r2morph/cli/tui_screens.py            # Screen definitions
r2morph/cli/tui_components.py          # Reusable components
tests/unit/test_tui.py                # Unit tests
```

### Key Classes

```python
class MutationTUI:
    def __init__(self, binary: Binary)
    def run(self) -> TUIResult
    def show_preview(self, mutation: Mutation) -> None
    def select_functions(self, funcs: list[Function]) -> list[Function]
    def select_passes(self) -> list[str]
    def confirm_mutations(self, plan: MutationPlan) -> bool
    def show_progress(self, progress: float, message: str) -> None

class TUIMainScreen(Screen):
    def render(self) -> None
    def handle_input(self, key: str) -> str

class TUIMutationPreview(Screen):
    def show_function_diff(self, addr: int) -> None
    def show_byte_diff(self, addr: int) -> None
    def show_semantic_check(self, check: str) -> None
    def show_before_after(self, addr: int) -> None

class TUIFunctionSelect(Screen):
    def render_functions(self, funcs: list[Function]) -> None
    def handle_selection(self, key: str) -> list[int]
    def search(self, pattern: str) -> None
    def sort_by(self, criteria: str) -> None

class TUIPassSelect(Screen):
    def render_passes(self, passes: list[MutationPass]) -> None
    def show_description(self, pass_name: str) -> None
    def show_dependencies(self, pass_name: str) -> None
    def validate_order(self) -> list[str]

class TUIConfirmScreen(Screen):
    def render_summary(self, plan: MutationPlan) -> None
    def handle_input(self, key: str) -> bool
```

### Implementation Steps

1. **Main TUI Framework**
   - Set up Rich framework
   - Create screen navigation
   - Handle keyboard input

2. **Function Selection Screen**
   - List functions with size/address
   - Search and filter
   - Multi-select support

3. **Pass Selection Screen**
   - List available passes
   - Show descriptions and dependencies
   - Validate order with PassDependencyRegistry
   - Reorder passes

4. **Preview Screen**
   - Show before/after disassembly
   - Highlight byte differences
   - Show semantic validation status

5. **Progress Screen**
   - Real-time mutation progress
   - Error handling
   - Cancel support

### Success Criteria

- Interactive UI works without docs
- All screens keyboard-navigable
- Supports search and filtering
- Progress updates in real-time
- Works on standard terminals

---

## 4.2 SARIF Output Format (v2.1.0)

### Goal
Support SARIF 2.1.0 output format for CI/CD integration with security tools.

### Files to Create

```
r2morph/reporting/sarif_formatter.py       # SARIF formatting
r2morph/reporting/sarif_schema.py          # Schema validation
tests/unit/test_sarif_formatter.py          # Unit tests
```

### SARIF 2.1.0 Schema

```python
@dataclass
class SARIFReport:
    schema_uri: str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    version: str = "2.1.0"
    runs: list[SARIFRun]
    
    def to_json(self) -> dict:
        return asdict(self)
    
    def write(self, path: Path) -> None:
        with open(path, 'w') as f:
            json.dump(self.to_json(), f, indent=2)

@dataclass
class SARIFRun:
    tool: SARIFTool
    results: list[SARIFResult]
    artifacts: list[SARIFArtifact]
    invocations: list[SARIFInvocation]

@dataclass
class SARIFTool:
    driver: SARIFComponent
    
@dataclass
class SARIFComponent:
    name: str
    version: str
    information_uri: str
    rules: list[SARIFRule]
    full_name: str | None = None

@dataclass
class SARIFRule:
    id: str
    name: str
    short_description: SARIFMessage
    full_description: SARIFMessage | None = None
    help_uri: str | None = None
    default_configuration: SARIFConfiguration | None = None

@dataclass
class SARIFResult:
    rule_id: str
    rule_index: int
    level: str  # "error", "warning", "note", "none"
    message: SARIFMessage
    locations: list[SARIFLocation]
    related_locations: list[SARIFLocation] | None = None
    fixes: list[SARIFFix] | None = None
    code_flows: list[SARIFCodeFlow] | None = None
    properties: dict[str, Any] | None = None

@dataclass
class SARIFLocation:
    physical_location: SARIFPhysicalLocation
    
@dataclass
class SARIFPhysicalLocation:
    artifact_location: SARIFArtifactLocation
    region: SARIFRegion

@dataclass
class SARIFRegion:
    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    byte_offset: int | None = None
    byte_length: int | None = None
    snippet: SARIFSnippet | None = None

@dataclass
class SARIFFix:
    description: SARIFMessage
    artifact_changes: list[SARIFArtifactChange]

@dataclass
class SARIFArtifactChange:
    artifact_location: SARIFArtifactLocation
    replacements: list[SARIFReplacement]

@dataclass
class SARIFReplacement:
    deleted_region: SARIFRegion
    inserted_content: SARIFContent

@dataclass
class SARIFCodeFlow:
    message: SARIFMessage | None = None
    thread_flows: list[SARIFThreadFlow]

@dataclass
class SARIFThreadFlow:
    locations: list[SARIFThreadFlowLocation]

@dataclass
class SARIFThreadFlowLocation:
    location: SARIFLocation
    nesting_level: int = 0
```

### Mapping

| r2morph Result | SARIF Level |
|----------------|-------------|
| Error | error |
| Warning | warning |
| Info | note |
| Pass | none |

### Implementation Steps

1. **Define SARIF Schema**
   - Create all SARIF 2.1.0 dataclasses
   - Add validation
   - Add JSON serialization

2. **Map Results to SARIF**
   - Map mutation results to findings
   - Map addresses to locations
   - Map semantic violations to rules

3. **Create Rules**
   - Define r2morph rule IDs
   - Create rule descriptions
   - Map pass names to rules

4. **CLI Integration**
   - Add `--format sarif` option
   - Add `--sarif-output` option
   - Support incremental results

### SARIF Rule Examples

```python
RULES = [
    SARIFRule(
        id="r2morph-semantic-mismatch",
        name="Semantic Equivalence Violation",
        short_description=SARIFMessage(text="Mutation may alter program semantics"),
        full_description=SARIFMessage(text="..."),
        default_configuration=SARIFConfiguration(level="error"),
    ),
    SARIFRule(
        id="r2morph-integrity-violation",
        name="Binary Integrity Violation",
        short_description=SARIFMessage(text="Mutation breaks binary integrity"),
        default_configuration=SARIFConfiguration(level="error"),
    ),
    # ... more rules
]
```

### Success Criteria

- Output validates against SARIF 2.1.0 schema
- Compatible with GitHub Advanced Security
- Compatible with SonarQube
- CI/CD integration documented

---

## 4.3 Analysis Cache

### Goal
Cache analysis results to speed up repeated runs.

### Files to Create

```
r2morph/core/analysis_cache.py       # Cache management
r2morph/core/cache_storage.py        # Storage backends
r2morph/core/cache_invalidator.py    # Cache invalidation
tests/unit/test_analysis_cache.py     # Unit tests
```

### Key Classes

```python
class AnalysisCache:
    def __init__(self, cache_dir: Path | None = None)
    def get(self, binary: Binary, analysis_type: str) -> Any | None
    def set(self, binary: Binary, analysis_type: str, result: Any) -> None
    def invalidate(self, binary: Binary) -> None
    def invalidate_region(self, addr: int, size: int) -> None
    def get_stats(self) -> CacheStats
    def clear(self) -> None

class CacheKey:
    binary_hash: str
    analysis_type: str
    options_hash: str
    version: str  # r2morph version
    
    @classmethod
    def from_binary(cls, binary: Binary, analysis_type: str, options: dict) -> CacheKey

class CacheStorage:
    def load(self, key: CacheKey) -> Any | None
    def save(self, key: CacheKey, data: Any) -> None
    def delete(self, key: CacheKey) -> None
    def exists(self, key: CacheKey) -> bool

class DiskCacheStorage(CacheStorage):
    def __init__(self, cache_dir: Path)
    # JSON + pickle serialization
    
class MemoryCacheStorage(CacheStorage):
    def __init__(self)
    # In-memory cache
    
class CacheStats:
    hits: int
    misses: int
    size: int  # bytes
    entries: int
    
    def hit_rate(self) -> float
```

### Implementation Steps

1. **Cache Key Generation**
   - Hash binary content
   - Include analysis type
   - Include options hash
   - Include r2morph version

2. **Storage Backend**
   - Disk-based JSON storage
   - Optional in-memory cache
   - Compression for large results

3. **Invalidation**
   - Track dependencies between analyses
   - Invalidate on binary change
   - Invalidate region on mutation

4. **CLI Integration**
   - Add `--cache` flag (default on)
   - Add `--clear-cache` flag
   - Add `--cache-dir` option

### Cacheable Analyses

| Analysis | Key | Dependencies |
|----------|-----|---------------|
| Functions | `func_{hash}` | None |
| CFG | `cfg_{hash}` | Functions |
| Call Graph | `cg_{hash}` | Functions |
| Type Inference | `type_{hash}_{func}` | CFG |
| Data Flow | `df_{hash}_{func}` | CFG, Types |
| Symbols | `sym_{hash}` | None |
| Strings | `str_{hash}` | None |

### Success Criteria

- 10x+ speedup on repeated analysis
- Cache survives across runs
- Handles dependency invalidation
- Minimal memory overhead
- Thread-safe

---

## Timeline

| Week | Task |
|------|------|
| 1-2 | TUI Framework & Navigation |
| 3-4 | Function/Pass Selection Screens |
| 5-6 | SARIF Formatter |
| 7-8 | Analysis Cache |
| 8-9 | Integration Testing |

---

## Dependencies

```
Phase 1-3 Complete
    └── Phase 4 (All features independent)
```

---

*Created: 2026-03-19*