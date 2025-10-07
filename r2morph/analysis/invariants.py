"""
Invariant detection and verification for binary code.

Detects code invariants that must be preserved during mutations.
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class InvariantType(Enum):
    """Types of code invariants."""

    STACK_BALANCE = "stack_balance"
    REGISTER_PRESERVATION = "reg_preserve"
    CALLING_CONVENTION = "call_conv"
    RETURN_VALUE = "return_value"
    CONTROL_FLOW = "control_flow"
    MEMORY_SAFETY = "memory_safety"


@dataclass
class Invariant:
    """
    Represents a code invariant that must be preserved.
    """

    invariant_type: InvariantType
    description: str
    location: int
    details: dict[str, Any]

    def __repr__(self) -> str:
        return f"<Invariant {self.invariant_type.value} @ 0x{self.location:x}: {self.description}>"


class InvariantDetector:
    """
    Detects invariants in binary code that must be preserved during mutation.
    """

    CALLEE_SAVED_REGS = {
        "x86": ["ebx", "esi", "edi", "ebp"],
        "x64": ["rbx", "r12", "r13", "r14", "r15", "rbp"],
        "arm": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
    }

    def __init__(self, binary: Binary):
        """
        Initialize invariant detector.

        Args:
            binary: Binary instance
        """
        self.binary = binary
        self.invariants: list[Invariant] = []

    def detect_stack_balance(self, function_address: int) -> list[Invariant]:
        """
        Detect stack balance invariants in a function.

        The stack must be balanced: pushes must match pops.

        Args:
            function_address: Function address

        Returns:
            List of stack balance invariants
        """
        invariants = []

        try:
            instructions = self.binary.get_function_disasm(function_address)
        except Exception as e:
            logger.debug(f"Failed to get disasm for function @ 0x{function_address:x}: {e}")
            return invariants

        stack_delta = 0
        push_count = 0
        pop_count = 0

        for insn in instructions:
            disasm = insn.get("disasm", "").lower()
            mnemonic = disasm.split()[0] if disasm else ""

            if mnemonic == "push":
                stack_delta -= 8
                push_count += 1
            elif mnemonic == "pop":
                stack_delta += 8
                pop_count += 1
            elif mnemonic in ["call"]:
                pass
            elif mnemonic in ["ret", "retn"]:
                if stack_delta != 0:
                    invariants.append(
                        Invariant(
                            invariant_type=InvariantType.STACK_BALANCE,
                            description=f"Stack unbalanced at return (delta={stack_delta})",
                            location=insn.get("offset", 0),
                            details={"delta": stack_delta, "pushes": push_count, "pops": pop_count},
                        )
                    )

        if push_count != pop_count:
            invariants.append(
                Invariant(
                    invariant_type=InvariantType.STACK_BALANCE,
                    description=f"Function has unbalanced push/pop ({push_count} push, {pop_count} pop)",
                    location=function_address,
                    details={"pushes": push_count, "pops": pop_count},
                )
            )

        return invariants

    def detect_register_preservation(self, function_address: int, arch: str) -> list[Invariant]:
        """
        Detect register preservation invariants.

        Callee-saved registers must be preserved across function calls.

        Args:
            function_address: Function address
            arch: Architecture name

        Returns:
            List of register preservation invariants
        """
        invariants = []

        arch_family = "x86" if arch in ["x86", "x64"] else arch
        callee_saved = set(self.CALLEE_SAVED_REGS.get(arch_family, []))

        if not callee_saved:
            return invariants

        try:
            instructions = self.binary.get_function_disasm(function_address)
        except Exception:
            return invariants

        modified_regs = set()
        saved_regs = set()
        restored_regs = set()

        for _i, insn in enumerate(instructions[:10]):
            disasm = insn.get("disasm", "").lower()
            parts = disasm.split()
            if len(parts) >= 2 and parts[0] == "push":
                reg = parts[1].strip(",")
                if reg in callee_saved:
                    saved_regs.add(reg)

        for _i, insn in enumerate(reversed(instructions[-10:])):
            disasm = insn.get("disasm", "").lower()
            parts = disasm.split()
            if len(parts) >= 2 and parts[0] == "pop":
                reg = parts[1].strip(",")
                if reg in callee_saved:
                    restored_regs.add(reg)

        for insn in instructions:
            disasm = insn.get("disasm", "").lower()
            parts = disasm.split()
            if not parts:
                continue

            mnemonic = parts[0]

            if len(parts) >= 2:
                if mnemonic in ["mov", "add", "sub", "xor", "or", "and", "lea"]:
                    dest_op = parts[1].split(",")[0]
                    if any(reg in dest_op for reg in callee_saved):
                        for reg in callee_saved:
                            if reg in dest_op:
                                modified_regs.add(reg)

        for reg in modified_regs:
            if reg not in saved_regs or reg not in restored_regs:
                invariants.append(
                    Invariant(
                        invariant_type=InvariantType.REGISTER_PRESERVATION,
                        description=f"Callee-saved register {reg} modified but not preserved",
                        location=function_address,
                        details={
                            "register": reg,
                            "saved": reg in saved_regs,
                            "restored": reg in restored_regs,
                        },
                    )
                )

        return invariants

    def detect_all_invariants(self, function_address: int) -> list[Invariant]:
        """
        Detect all invariants for a function.

        Args:
            function_address: Function address

        Returns:
            List of all detected invariants
        """
        arch_info = self.binary.get_arch_info()
        arch = arch_info.get("arch", "unknown")

        invariants = []

        invariants.extend(self.detect_stack_balance(function_address))
        invariants.extend(self.detect_register_preservation(function_address, arch))

        logger.debug(f"Detected {len(invariants)} invariants for function @ 0x{function_address:x}")

        return invariants

    def verify_invariants(
        self, function_address: int, expected_invariants: list[Invariant]
    ) -> list[Invariant]:
        """
        Verify that expected invariants still hold.

        Args:
            function_address: Function address
            expected_invariants: List of invariants that should hold

        Returns:
            List of violated invariants
        """
        current_invariants = self.detect_all_invariants(function_address)

        violated = []

        for expected in expected_invariants:
            found = any(
                inv.invariant_type == expected.invariant_type and inv.location == expected.location
                for inv in current_invariants
            )

            if not found:
                violated.append(expected)

        return violated


class SemanticValidator:
    """
    Validates that mutations preserve program semantics.
    """

    def __init__(self, binary: Binary):
        """
        Initialize semantic validator.

        Args:
            binary: Binary instance
        """
        self.binary = binary
        self.detector = InvariantDetector(binary)

    def validate_mutation(
        self, function_address: int, original_invariants: list[Invariant] | None = None
    ) -> dict[str, Any]:
        """
        Validate that a mutation preserves semantics.

        Args:
            function_address: Function address
            original_invariants: Original invariants to check against

        Returns:
            Dictionary with validation results
        """
        if original_invariants is None:
            logger.warning("No original invariants provided, skipping validation")
            return {"valid": True, "violations": []}

        violations = self.detector.verify_invariants(function_address, original_invariants)

        is_valid = len(violations) == 0

        result = {
            "valid": is_valid,
            "violations": violations,
            "violation_count": len(violations),
        }

        if not is_valid:
            logger.warning(
                f"Function @ 0x{function_address:x} has {len(violations)} "
                f"invariant violations after mutation"
            )
            for violation in violations:
                logger.debug(f"  Violation: {violation}")

        return result

    def batch_validate(
        self, function_addresses: list[int], invariants_map: dict[int, list[Invariant]]
    ) -> Dict[str, Any]:
        """
        Validate multiple functions at once.

        Args:
            function_addresses: List of function addresses
            invariants_map: Map of function address to original invariants

        Returns:
            Dictionary with batch validation results
        """
        results = {}
        total_violations = 0

        for addr in function_addresses:
            original_invs = invariants_map.get(addr, [])
            result = self.validate_mutation(addr, original_invs)
            results[addr] = result
            total_violations += result["violation_count"]

        return {
            "functions_validated": len(function_addresses),
            "total_violations": total_violations,
            "all_valid": total_violations == 0,
            "results": results,
        }
