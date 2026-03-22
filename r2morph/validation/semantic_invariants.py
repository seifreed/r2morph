"""
Semantic invariants for mutation passes.

This module defines pass-level invariants that must be preserved during mutations:
- Stack balance
- Register preservation
- Side-effect constraints
- Control flow preservation
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class InvariantCategory(Enum):
    """Category of semantic invariant."""

    STACK = "stack"
    REGISTER = "register"
    MEMORY = "memory"
    CONTROL_FLOW = "control_flow"
    SIDE_EFFECT = "side_effect"
    ABI = "abi"


class InvariantSeverity(Enum):
    """Severity level for invariant violations."""

    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class InvariantSpec:
    """Specification of a semantic invariant."""

    name: str
    category: InvariantCategory
    description: str
    check_required: bool = True
    auto_repair: bool = False
    pass_types: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class InvariantViolation:
    """Represents a violation of a semantic invariant."""

    invariant_name: str
    category: InvariantCategory
    severity: InvariantSeverity
    address_range: tuple[int, int]
    message: str
    expected: Any | None = None
    actual: Any | None = None
    repair_hint: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "invariant_name": self.invariant_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "address_range": [self.address_range[0], self.address_range[1]],
            "message": self.message,
            "expected": str(self.expected) if self.expected else None,
            "actual": str(self.actual) if self.actual else None,
            "repair_hint": self.repair_hint,
            "metadata": self.metadata,
        }


class SemanticInvariantRegistry:
    """Registry of semantic invariants for mutation passes."""

    STANDARD_INVARIANTS: list[InvariantSpec] = [
        InvariantSpec(
            name="stack_balance",
            category=InvariantCategory.STACK,
            description="Stack pointer must return to original value after function",
            check_required=True,
            pass_types=["nop", "substitute", "register", "block"],
        ),
        InvariantSpec(
            name="callee_saved_preservation",
            category=InvariantCategory.REGISTER,
            description="Callee-saved registers must be preserved",
            check_required=True,
            pass_types=["nop", "substitute", "register"],
        ),
        InvariantSpec(
            name="return_value_preservation",
            category=InvariantCategory.REGISTER,
            description="Return value register(s) must contain correct value",
            check_required=True,
            auto_repair=False,
            pass_types=["substitute", "register"],
        ),
        InvariantSpec(
            name="control_flow_preservation",
            category=InvariantCategory.CONTROL_FLOW,
            description="Control flow must reach original successors",
            check_required=True,
            pass_types=["nop", "substitute", "register", "block"],
        ),
        InvariantSpec(
            name="memory_safety",
            category=InvariantCategory.MEMORY,
            description="Memory accesses must not exceed bounds",
            check_required=True,
            pass_types=["substitute", "register"],
        ),
        InvariantSpec(
            name="no_unintended_writes",
            category=InvariantCategory.SIDE_EFFECT,
            description="Mutation must not introduce unintended memory writes",
            check_required=True,
            pass_types=["substitute", "register"],
        ),
    ]

    def __init__(self) -> None:
        """Initialize the invariant registry."""
        self._invariants: dict[str, InvariantSpec] = {inv.name: inv for inv in self.STANDARD_INVARIANTS}
        self._pass_invariants: dict[str, list[str]] = {}
        self._build_pass_index()

    def _build_pass_index(self) -> None:
        """Build index of invariants by pass type."""
        self._pass_invariants = {}
        for inv in self._invariants.values():
            for pass_type in inv.pass_types:
                if pass_type not in self._pass_invariants:
                    self._pass_invariants[pass_type] = []
                self._pass_invariants[pass_type].append(inv.name)

    def register_invariant(self, invariant: InvariantSpec) -> None:
        """Register a new invariant."""
        self._invariants[invariant.name] = invariant
        self._build_pass_index()

    def get_invariants_for_pass(self, pass_type: str) -> list[InvariantSpec]:
        """Get all invariants that apply to a pass type."""
        return [self._invariants[name] for name in self._pass_invariants.get(pass_type, []) if name in self._invariants]

    def get_required_invariants(self, pass_type: str) -> list[InvariantSpec]:
        """Get only required invariants for a pass type."""
        return [inv for inv in self.get_invariants_for_pass(pass_type) if inv.check_required]


class StackBalanceChecker:
    """Checks stack balance invariants for mutated code."""

    ARCH_STACK_REG = {
        "x86": ("esp", 32),
        "x86_64": ("rsp", 64),
        "arm": ("sp", 32),
        "arm64": ("sp", 64),
    }

    def __init__(self, binary: Binary) -> None:
        """Initialize stack balance checker."""
        self.binary = binary

    def check_region(
        self,
        start_address: int,
        end_address: int,
        original_bytes: bytes,
        mutated_bytes: bytes,
    ) -> list[InvariantViolation]:
        """
        Check stack balance for a mutated region.

        Args:
            start_address: Start address of region
            end_address: End address of region
            original_bytes: Original bytes before mutation
            mutated_bytes: Bytes after mutation

        Returns:
            List of violations found
        """
        violations: list[InvariantViolation] = []

        arch_info = self.binary.get_arch_info()
        arch = arch_info.get("arch", "")
        bits = arch_info.get("bits", 64)

        if "x86" in arch or arch == "x86_64":
            arch = "x86_64" if bits == 64 else "x86"
        elif "arm" in arch:
            arch = "arm64" if bits == 64 else "arm"

        stack_word_size = bits // 8

        original_stack_delta = self._compute_stack_delta_for_bytes(original_bytes, arch, stack_word_size)
        mutated_stack_delta = self._compute_stack_delta_for_bytes(mutated_bytes, arch, stack_word_size)

        if original_stack_delta != mutated_stack_delta:
            violations.append(
                InvariantViolation(
                    invariant_name="stack_balance",
                    category=InvariantCategory.STACK,
                    severity=InvariantSeverity.ERROR,
                    address_range=(start_address, end_address),
                    message="Stack balance changed after mutation",
                    expected=original_stack_delta,
                    actual=mutated_stack_delta,
                    repair_hint="Ensure push/pop instructions balance",
                )
            )

        return violations

    def _compute_stack_delta_for_bytes(
        self,
        code_bytes: bytes,
        arch: str,
        word_size: int,
    ) -> int:
        """Compute net stack delta from instruction bytes."""
        delta = 0

        push_opcodes = {
            "x86": [b"\x50", b"\x51", b"\x52", b"\x53", b"\x54", b"\x55", b"\x56", b"\x57"],
            "x86_64": [b"\x50", b"\x51", b"\x52", b"\x53", b"\x54", b"\x55", b"\x56", b"\x57"],
        }
        pop_opcodes = {
            "x86": [b"\x58", b"\x59", b"\x5a", b"\x5b", b"\x5c", b"\x5d", b"\x5e", b"\x5f"],
            "x86_64": [b"\x58", b"\x59", b"\x5a", b"\x5b", b"\x5c", b"\x5d", b"\x5e", b"\x5f"],
        }

        if arch not in push_opcodes:
            return delta

        for i in range(len(code_bytes)):
            for push_op in push_opcodes.get(arch, []):
                if code_bytes[i : i + len(push_op)] == push_op:
                    delta -= word_size
                    break

            for pop_op in pop_opcodes.get(arch, []):
                if code_bytes[i : i + len(pop_op)] == pop_op:
                    delta += word_size
                    break

            if code_bytes[i : i + 2] == b"\x68":
                delta -= word_size
            elif code_bytes[i : i + 2] == b"\x8f":
                delta += word_size

        return delta


class RegisterPreservationChecker:
    """Checks register preservation invariants."""

    CALLEE_SAVED = {
        "x86": ["ebx", "esi", "edi", "ebp"],
        "x86_64": ["rbx", "r12", "r13", "r14", "r15", "rbp"],
        "arm": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
        "arm64": ["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29"],
    }

    def __init__(self, binary: Binary) -> None:
        """Initialize register preservation checker."""
        self.binary = binary

    def get_callee_saved_registers(self) -> list[str]:
        """Get list of callee-saved registers for current architecture."""
        arch_info = self.binary.get_arch_info()
        arch = arch_info.get("arch", "")
        bits = arch_info.get("bits", 64)

        if "x86" in arch:
            key = "x86_64" if bits == 64 else "x86"
        elif "arm" in arch:
            key = "arm64" if bits == 64 else "arm"
        else:
            return []

        return self.CALLEE_SAVED.get(key, [])

    def check_register_usage(
        self,
        start_address: int,
        end_address: int,
        pass_type: str,
        mutated_registers: set[str],
    ) -> list[InvariantViolation]:
        """
        Check if mutation preserves required registers.

        Args:
            start_address: Start address of mutation
            end_address: End address of mutation
            pass_type: Type of mutation pass
            mutated_registers: Set of registers modified by mutation

        Returns:
            List of violations found
        """
        violations: list[InvariantViolation] = []

        callee_saved = set(self.get_callee_saved_registers())

        for reg in mutated_registers:
            reg_lower = reg.lower()
            if reg_lower in {r.lower() for r in callee_saved}:
                violations.append(
                    InvariantViolation(
                        invariant_name="callee_saved_preservation",
                        category=InvariantCategory.REGISTER,
                        severity=InvariantSeverity.WARNING,
                        address_range=(start_address, end_address),
                        message=f"Mutation modifies callee-saved register {reg}",
                        expected=f"{reg} preserved",
                        actual=f"{reg} modified",
                        repair_hint=f"Save and restore {reg} around mutation",
                    )
                )

        return violations


class ControlFlowPreservationChecker:
    """Checks control flow preservation invariants."""

    def __init__(self, binary: Binary) -> None:
        """Initialize control flow preservation checker."""
        self.binary = binary

    def check_successor_preservation(
        self,
        start_address: int,
        end_address: int,
        original_successors: list[int],
        mutated_successors: list[int],
    ) -> list[InvariantViolation]:
        """
        Check if mutation preserves control flow successors.

        Args:
            start_address: Start address of mutation
            end_address: End address of mutation
            original_successors: Original successor addresses
            mutated_successors: Mutated successor addresses

        Returns:
            List of violations found
        """
        violations: list[InvariantViolation] = []

        original_set = set(original_successors)
        mutated_set = set(mutated_successors)

        missing = original_set - mutated_set
        extra = mutated_set - original_set

        if missing:
            violations.append(
                InvariantViolation(
                    invariant_name="control_flow_preservation",
                    category=InvariantCategory.CONTROL_FLOW,
                    severity=InvariantSeverity.ERROR,
                    address_range=(start_address, end_address),
                    message="Mutation removed control flow successors",
                    expected=list(original_set),
                    actual=list(mutated_set),
                    repair_hint="Ensure all original branch targets are still reachable",
                )
            )

        if extra:
            violations.append(
                InvariantViolation(
                    invariant_name="control_flow_preservation",
                    category=InvariantCategory.CONTROL_FLOW,
                    severity=InvariantSeverity.WARNING,
                    address_range=(start_address, end_address),
                    message="Mutation added control flow successors",
                    expected=list(original_set),
                    actual=list(mutated_set),
                    repair_hint="Verify new branch targets are intentional",
                )
            )

        return violations


class SemanticInvariantChecker:
    """
    Main class for checking semantic invariants.

    Provides unified interface for all invariant checks.
    """

    def __init__(self, binary: Binary) -> None:
        """Initialize semantic invariant checker."""
        self.binary = binary
        self.registry = SemanticInvariantRegistry()
        self.stack_checker = StackBalanceChecker(binary)
        self.register_checker = RegisterPreservationChecker(binary)
        self.cf_checker = ControlFlowPreservationChecker(binary)

    def check_mutation(
        self,
        pass_type: str,
        start_address: int,
        end_address: int,
        original_bytes: bytes,
        mutated_bytes: bytes,
        original_successors: list[int] | None = None,
        mutated_successors: list[int] | None = None,
        mutated_registers: set[str] | None = None,
    ) -> list[InvariantViolation]:
        """
        Check all invariants for a mutation.

        Args:
            pass_type: Type of mutation pass
            start_address: Start address of mutation
            end_address: End address of mutation
            original_bytes: Original bytes
            mutated_bytes: Mutated bytes
            original_successors: Original control flow successors
            mutated_successors: Mutated control flow successors
            mutated_registers: Set of modified registers

        Returns:
            List of all violations found
        """
        violations: list[InvariantViolation] = []

        invariants = self.registry.get_invariants_for_pass(pass_type)

        for inv in invariants:
            if inv.category == InvariantCategory.STACK:
                violations.extend(
                    self.stack_checker.check_region(start_address, end_address, original_bytes, mutated_bytes)
                )

            elif inv.category == InvariantCategory.REGISTER:
                if mutated_registers:
                    violations.extend(
                        self.register_checker.check_register_usage(
                            start_address, end_address, pass_type, mutated_registers
                        )
                    )

            elif inv.category == InvariantCategory.CONTROL_FLOW:
                if original_successors is not None and mutated_successors is not None:
                    violations.extend(
                        self.cf_checker.check_successor_preservation(
                            start_address,
                            end_address,
                            original_successors,
                            mutated_successors,
                        )
                    )

        return violations

    def get_invariant_summary(self, violations: list[InvariantViolation]) -> dict[str, Any]:
        """
        Generate summary of invariant violations.

        Args:
            violations: List of violations

        Returns:
            Summary dictionary
        """
        by_category: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        critical_violations: list[dict[str, Any]] = []

        for v in violations:
            cat = v.category.value
            sev = v.severity.value
            by_category[cat] = by_category.get(cat, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1

            if v.severity == InvariantSeverity.CRITICAL:
                critical_violations.append(v.to_dict())

        return {
            "total_violations": len(violations),
            "by_category": by_category,
            "by_severity": by_severity,
            "critical_violations": critical_violations,
            "passed": len(critical_violations) == 0 and len(violations) == 0,
        }
