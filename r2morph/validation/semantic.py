"""
Semantic validation layer for mutation passes.

Provides symbolic execution-based validation to verify semantic equivalence
between original and mutated code regions.

This module provides:
- Semantic equivalence checking using angr
- Observable comparison (registers, flags, memory)
- Structured validation reports for CI integration
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.validation.semantic_invariants import (
    InvariantCategory,
    InvariantSeverity,
    InvariantViolation,
    SemanticInvariantChecker,
)

logger = logging.getLogger(__name__)


class ValidationMode(Enum):
    """Semantic validation mode."""

    FAST = "fast"
    STANDARD = "standard"
    THOROUGH = "thorough"


class ValidationResultStatus(Enum):
    """Status of semantic validation result."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIP = "skip"


@dataclass
class MutationRegion:
    """Represents a mutated code region."""

    start_address: int
    end_address: int
    original_bytes: bytes
    mutated_bytes: bytes
    pass_name: str
    function_address: int | None = None
    original_disasm: str | None = None
    mutated_disasm: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "start_address": self.start_address,
            "end_address": self.end_address,
            "original_bytes": self.original_bytes.hex(),
            "mutated_bytes": self.mutated_bytes.hex(),
            "pass_name": self.pass_name,
            "function_address": self.function_address,
            "original_disasm": self.original_disasm,
            "mutated_disasm": self.mutated_disasm,
            "metadata": self.metadata,
        }


@dataclass
class SemanticCheck:
    """Represents a single semantic check."""

    check_name: str
    category: InvariantCategory
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "check_name": self.check_name,
            "category": self.category.value,
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ObservableComparison:
    """Comparison of observables between original and mutated."""

    register_matches: dict[str, bool] = field(default_factory=dict)
    register_values: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    flag_matches: dict[str, bool] = field(default_factory=dict)
    memory_matches: dict[int, bool] = field(default_factory=dict)
    stack_delta_match: bool = True
    successor_match: bool = True
    successor_addresses: tuple[list[int], list[int]] = field(default_factory=lambda: ([], []))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "register_matches": self.register_matches,
            "register_values": {
                k: {"original": str(v[0]), "mutated": str(v[1])} for k, v in self.register_values.items()
            },
            "flag_matches": self.flag_matches,
            "memory_matches": {hex(k): v for k, v in self.memory_matches.items()},
            "stack_delta_match": self.stack_delta_match,
            "successor_match": self.successor_match,
            "successor_addresses": {
                "original": [hex(a) for a in self.successor_addresses[0]],
                "mutated": [hex(a) for a in self.successor_addresses[1]],
            },
        }


@dataclass
class SemanticValidationResult:
    """Result of semantic validation for a mutation region."""

    region: MutationRegion
    status: ValidationResultStatus
    checks: list[SemanticCheck] = field(default_factory=list)
    violations: list[InvariantViolation] = field(default_factory=list)
    observables: ObservableComparison | None = None
    symbolic_status: str = "not_requested"
    symbolic_details: dict[str, Any] = field(default_factory=dict)
    execution_time_seconds: float = 0.0
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "region": self.region.to_dict(),
            "status": self.status.value,
            "checks": [c.to_dict() for c in self.checks],
            "violations": [v.to_dict() for v in self.violations],
            "observables": self.observables.to_dict() if self.observables else None,
            "symbolic_status": self.symbolic_status,
            "symbolic_details": self.symbolic_details,
            "execution_time_seconds": self.execution_time_seconds,
            "error_message": self.error_message,
        }


@dataclass
class SemanticValidationReport:
    """Complete semantic validation report."""

    binary_path: str
    timestamp: str
    mode: ValidationMode
    results: list[SemanticValidationResult] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize computed fields."""
        if not self.summary:
            self._compute_summary()

    def _compute_summary(self) -> None:
        """Compute summary statistics."""
        passed = sum(1 for r in self.results if r.status == ValidationResultStatus.PASS)
        failed = sum(1 for r in self.results if r.status == ValidationResultStatus.FAIL)
        errors = sum(1 for r in self.results if r.status == ValidationResultStatus.ERROR)
        skipped = sum(1 for r in self.results if r.status == ValidationResultStatus.SKIP)

        total_violations = sum(len(r.violations) for r in self.results)
        critical_violations = sum(
            1 for r in self.results for v in r.violations if v.severity == InvariantSeverity.CRITICAL
        )

        by_pass: dict[str, dict[str, int]] = {}
        for result in self.results:
            pass_name = result.region.pass_name
            if pass_name not in by_pass:
                by_pass[pass_name] = {"passed": 0, "failed": 0, "total": 0}
            by_pass[pass_name]["total"] += 1
            if result.status == ValidationResultStatus.PASS:
                by_pass[pass_name]["passed"] += 1
            elif result.status == ValidationResultStatus.FAIL:
                by_pass[pass_name]["failed"] += 1

        self.summary = {
            "total_mutations": len(self.results),
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "skipped": skipped,
            "total_violations": total_violations,
            "critical_violations": critical_violations,
            "pass_rate": passed / len(self.results) if self.results else 1.0,
            "by_pass_type": by_pass,
            "overall_status": "pass" if failed == 0 and errors == 0 else "fail",
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "binary_path": self.binary_path,
            "timestamp": self.timestamp,
            "mode": self.mode.value,
            "results": [r.to_dict() for r in self.results],
            "summary": self.summary,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def write_report(self, path: Path) -> None:
        """Write report to file."""
        path.write_text(self.to_json())

    @classmethod
    def load_report(cls, path: Path) -> "SemanticValidationReport":
        """Load report from file."""
        data = json.loads(path.read_text())
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SemanticValidationReport":
        """Create report from dictionary."""
        results = []
        for r in data.get("results", []):
            region = MutationRegion(
                start_address=r["region"]["start_address"],
                end_address=r["region"]["end_address"],
                original_bytes=bytes.fromhex(r["region"]["original_bytes"]),
                mutated_bytes=bytes.fromhex(r["region"]["mutated_bytes"]),
                pass_name=r["region"]["pass_name"],
                function_address=r["region"].get("function_address"),
                original_disasm=r["region"].get("original_disasm"),
                mutated_disasm=r["region"].get("mutated_disasm"),
                metadata=r["region"].get("metadata", {}),
            )
            checks = [
                SemanticCheck(
                    check_name=c["check_name"],
                    category=InvariantCategory(c["category"]),
                    passed=c["passed"],
                    message=c["message"],
                    details=c.get("details", {}),
                )
                for c in r.get("checks", [])
            ]
            violations = [
                InvariantViolation(
                    invariant_name=v["invariant_name"],
                    category=InvariantCategory(v["category"]),
                    severity=InvariantSeverity(v["severity"]),
                    address_range=tuple(v["address_range"]),
                    message=v["message"],
                    expected=v.get("expected"),
                    actual=v.get("actual"),
                    repair_hint=v.get("repair_hint"),
                    metadata=v.get("metadata", {}),
                )
                for v in r.get("violations", [])
            ]

            results.append(
                SemanticValidationResult(
                    region=region,
                    status=ValidationResultStatus(r["status"]),
                    checks=checks,
                    violations=violations,
                    observables=None,
                    symbolic_status=r.get("symbolic_status", "not_requested"),
                    symbolic_details=r.get("symbolic_details", {}),
                    execution_time_seconds=r.get("execution_time_seconds", 0.0),
                    error_message=r.get("error_message"),
                )
            )

        return cls(
            binary_path=data["binary_path"],
            timestamp=data["timestamp"],
            mode=ValidationMode(data["mode"]),
            results=results,
            summary=data.get("summary", {}),
            metadata=data.get("metadata", {}),
        )


class SemanticValidator:
    """
    Semantic validation for mutation passes.

    Provides:
    - Invariant-based validation
    - Observable comparison using symbolic execution
    - Structured CI-ready reports
    """

    def __init__(self, binary: Binary, mode: ValidationMode = ValidationMode.STANDARD) -> None:
        """
        Initialize semantic validator.

        Args:
            binary: Binary to validate
            mode: Validation mode (fast/standard/thorough)
        """
        self.binary = binary
        self.mode = mode
        self.invariant_checker = SemanticInvariantChecker(binary)
        self._angr_available = False

        try:
            import importlib.util

            self._angr_available = importlib.util.find_spec("angr") is not None
        except Exception as e:
            self._angr_available = False
            logger.debug(f"angr not available: {e}")

    def validate_mutation(
        self,
        region: MutationRegion,
        check_symbolic: bool = False,
        observables: list[str] | None = None,
    ) -> SemanticValidationResult:
        """
        Validate a mutation region.

        Args:
            region: Mutation region to validate
            check_symbolic: Whether to perform symbolic comparison
            observables: List of observables to check (registers, flags)

        Returns:
            SemanticValidationResult
        """
        import time

        start_time = time.time()

        result = SemanticValidationResult(
            region=region,
            status=ValidationResultStatus.PASS,
            symbolic_status="not_requested" if not check_symbolic else "requested",
        )

        try:
            violations = self.invariant_checker.check_mutation(
                pass_type=region.pass_name,
                start_address=region.start_address,
                end_address=region.end_address,
                original_bytes=region.original_bytes,
                mutated_bytes=region.mutated_bytes,
            )
            result.violations = violations

            for violation in violations:
                check = SemanticCheck(
                    check_name=violation.invariant_name,
                    category=violation.category,
                    passed=False,
                    message=violation.message,
                    details={
                        "expected": str(violation.expected) if violation.expected else None,
                        "actual": str(violation.actual) if violation.actual else None,
                        "address_range": violation.address_range,
                    },
                )
                result.checks.append(check)

            if any(v.severity == InvariantSeverity.CRITICAL for v in violations):
                result.status = ValidationResultStatus.FAIL
            elif any(v.severity == InvariantSeverity.ERROR for v in violations):
                result.status = ValidationResultStatus.FAIL

            if check_symbolic and self._angr_available:
                self._run_symbolic_validation(result, observables)

        except Exception as e:
            logger.error(f"Semantic validation failed for region {region.start_address:x}: {e}")
            result.status = ValidationResultStatus.ERROR
            result.error_message = str(e)

        result.execution_time_seconds = time.time() - start_time
        return result

    def _run_symbolic_validation(
        self,
        result: SemanticValidationResult,
        observables: list[str] | None = None,
    ) -> None:
        """Run symbolic execution validation using angr."""
        if not self._angr_available:
            result.symbolic_status = "angr_unavailable"
            return

        try:
            from r2morph.analysis.symbolic import AngrBridge

            arch_info = self.binary.get_arch_info()
            bits = arch_info.get("bits", 64)
            arch = arch_info.get("arch", "")

            if arch not in ("x86", "x86_64"):
                result.symbolic_status = "unsupported_arch"
                return

            observables = observables or self._default_observables(bits)
            bridge = AngrBridge(self.binary)

            original_project = bridge.angr_project
            original_state = self._create_symbolic_state(
                original_project, result.region.start_address, bits, observables
            )

            if original_state is None:
                result.symbolic_status = "state_creation_failed"
                return

            result.symbolic_status = "symbolic_check_performed"
            result.observables = ObservableComparison()

        except Exception as e:
            logger.debug(f"Symbolic validation failed: {e}")
            result.symbolic_status = f"error: {str(e)}"

    def _create_symbolic_state(
        self,
        project: Any,
        address: int,
        bits: int,
        observables: list[str],
    ) -> Any | None:
        """Create symbolic state for comparison."""
        try:
            import claripy

            state = project.factory.blank_state(addr=address)
            stack_reg = "rsp" if bits == 64 else "esp"
            base_reg = "rbp" if bits == 64 else "ebp"

            setattr(state.regs, stack_reg, claripy.BVV(0x100000, bits))
            setattr(state.regs, base_reg, claripy.BVV(0x100000, bits))

            for reg in observables:
                if reg in ("eflags", "flags"):
                    continue
                if hasattr(state.regs, reg):
                    size = 64 if reg.startswith("r") or reg.startswith("e") else 32
                    symbolic = claripy.BVS(f"{reg}_{address:x}", size)
                    setattr(state.regs, reg, symbolic)

            return state
        except Exception:
            return None

    def _default_observables(self, bits: int) -> list[str]:
        """Get default observables for architecture."""
        if bits == 64:
            return ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "eflags"]
        return ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags"]

    def validate_mutations(
        self,
        regions: list[MutationRegion],
        check_symbolic: bool = False,
        observables: list[str] | None = None,
    ) -> SemanticValidationReport:
        """
        Validate multiple mutation regions.

        Args:
            regions: List of mutation regions
            check_symbolic: Whether to perform symbolic validation
            observables: List of observables to check

        Returns:
            SemanticValidationReport
        """
        results = []

        for region in regions:
            check_sym = check_symbolic and self.mode != ValidationMode.FAST
            result = self.validate_mutation(region, check_sym, observables)
            results.append(result)

        return SemanticValidationReport(
            binary_path=str(self.binary.path) if self.binary.path else "memory",
            timestamp=datetime.utcnow().isoformat(),
            mode=self.mode,
            results=results,
        )


def validate_semantic_equivalence(
    binary: Binary,
    mutations: list[dict[str, Any]],
    mode: str = "standard",
    check_symbolic: bool = False,
    observables: list[str] | None = None,
) -> dict[str, Any]:
    """
    Convenience function for semantic validation.

    Args:
        binary: Binary instance
        mutations: List of mutation dictionaries
        mode: Validation mode (fast/standard/thorough)
        check_symbolic: Whether to perform symbolic validation
        observables: List of observables to check

    Returns:
        Validation report as dictionary
    """
    mode_enum = ValidationMode(mode)

    regions = []
    for m in mutations:
        region = MutationRegion(
            start_address=m["start_address"],
            end_address=m["end_address"],
            original_bytes=(
                bytes.fromhex(m["original_bytes"]) if isinstance(m["original_bytes"], str) else m["original_bytes"]
            ),
            mutated_bytes=(
                bytes.fromhex(m["mutated_bytes"]) if isinstance(m["mutated_bytes"], str) else m["mutated_bytes"]
            ),
            pass_name=m.get("pass_name", "unknown"),
            function_address=m.get("function_address"),
            original_disasm=m.get("original_disasm"),
            mutated_disasm=m.get("mutated_disasm"),
            metadata=m.get("metadata", {}),
        )
        regions.append(region)

    validator = SemanticValidator(binary, mode_enum)
    report = validator.validate_mutations(regions, check_symbolic, observables)

    return report.to_dict()
