"""
ABI (Application Binary Interface) invariant checking for mutation passes.

This module provides platform/arch-specific ABI validation to ensure
mutations preserve calling conventions and platform requirements.

Supported ABIs:
- x86_64 System V (Linux/macOS): 16-byte stack alignment, red zone
- x86_64 Windows: 16-byte alignment, shadow space
- AArch64 (ARM64): 16-byte stack alignment
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class ABIType(Enum):
    """Supported ABI types."""

    X86_64_SYSTEM_V = "x86_64_sysv"
    X86_64_WINDOWS = "x86_64_windows"
    X86_32_LINUX = "x86_32_linux"
    X86_32_WINDOWS = "x86_32_windows"
    ARM64_AAPCS = "arm64_aapcs"
    ARM32_AAPCS = "arm32_aapcs"
    UNKNOWN = "unknown"


class ABIViolationType(Enum):
    """Types of ABI violations."""

    STACK_ALIGNMENT = "stack_alignment"
    RED_ZONE_CLOBBER = "red_zone_clobber"
    SHADOW_SPACE_VIOLATION = "shadow_space_violation"
    CALLEE_SAVED_CLOBBER = "callee_saved_clobber"
    CALLING_CONVENTION = "calling_convention"


@dataclass
class ABIViolation:
    """
    Represents an ABI violation detected during mutation.
    """

    violation_type: ABIViolationType
    description: str
    location: int
    details: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"<ABIViolation {self.violation_type.value} @ 0x{self.location:x}: {self.description}>"


@dataclass
class ABISpec:
    """
    ABI specification for a platform/architecture combination.
    """

    abi_type: ABIType
    stack_alignment: int
    red_zone_size: int
    shadow_space_size: int
    callee_saved_regs: list[str]
    param_regs: list[str]
    return_regs: list[str]

    def __repr__(self) -> str:
        return f"<ABISpec {self.abi_type.value}: align={self.stack_alignment}, red_zone={self.red_zone_size}, shadow={self.shadow_space_size}>"


ABI_SPECS: dict[str, ABISpec] = {
    "x86_64_sysv": ABISpec(
        abi_type=ABIType.X86_64_SYSTEM_V,
        stack_alignment=16,
        red_zone_size=128,
        shadow_space_size=0,
        callee_saved_regs=["rbx", "r12", "r13", "r14", "r15", "rbp"],
        param_regs=["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        return_regs=["rax", "rdx"],
    ),
    "x86_64_windows": ABISpec(
        abi_type=ABIType.X86_64_WINDOWS,
        stack_alignment=16,
        red_zone_size=0,
        shadow_space_size=32,
        callee_saved_regs=["rbx", "rdi", "rsi", "r12", "r13", "r14", "r15", "rbp"],
        param_regs=["rcx", "rdx", "r8", "r9"],
        return_regs=["rax"],
    ),
    "x86_32_linux": ABISpec(
        abi_type=ABIType.X86_32_LINUX,
        stack_alignment=4,
        red_zone_size=0,
        shadow_space_size=0,
        callee_saved_regs=["ebx", "esi", "edi", "ebp"],
        param_regs=[],
        return_regs=["eax", "edx"],
    ),
    "x86_32_windows": ABISpec(
        abi_type=ABIType.X86_32_WINDOWS,
        stack_alignment=4,
        red_zone_size=0,
        shadow_space_size=0,
        callee_saved_regs=["ebx", "esi", "edi", "ebp"],
        param_regs=[],
        return_regs=["eax", "edx"],
    ),
    "arm64_aapcs": ABISpec(
        abi_type=ABIType.ARM64_AAPCS,
        stack_alignment=16,
        red_zone_size=0,
        shadow_space_size=0,
        callee_saved_regs=["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30"],
        param_regs=["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
        return_regs=["x0", "x1"],
    ),
    "arm32_aapcs": ABISpec(
        abi_type=ABIType.ARM32_AAPCS,
        stack_alignment=8,
        red_zone_size=0,
        shadow_space_size=0,
        callee_saved_regs=["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
        param_regs=["r0", "r1", "r2", "r3"],
        return_regs=["r0", "r1"],
    ),
}


def detect_abi(binary: Binary) -> ABISpec:
    """
    Detect the ABI for a binary.

    Args:
        binary: Binary instance

    Returns:
        ABISpec for the detected ABI
    """
    arch_info = binary.get_arch_info()
    arch = arch_info.get("arch", "").lower()
    bits = arch_info.get("bits", 64)
    platform = arch_info.get("platform", "").lower()

    if "arm" in arch or "aarch" in arch:
        if bits == 64:
            return ABI_SPECS["arm64_aapcs"]
        return ABI_SPECS["arm32_aapcs"]

    if "x86" in arch or "8086" in arch or "amd" in arch or arch == "intel":
        if bits == 64:
            if "windows" in platform or "pe" in platform:
                return ABI_SPECS["x86_64_windows"]
            return ABI_SPECS["x86_64_sysv"]
        if "windows" in platform or "pe" in platform:
            return ABI_SPECS["x86_32_windows"]
        return ABI_SPECS["x86_32_linux"]

    return ABISpec(
        abi_type=ABIType.UNKNOWN,
        stack_alignment=16,
        red_zone_size=0,
        shadow_space_size=0,
        callee_saved_regs=[],
        param_regs=[],
        return_regs=[],
    )


class ABIChecker:
    """
    Check ABI invariants before and after mutations.
    """

    def __init__(self, binary: Binary, abi_spec: ABISpec | None = None):
        """
        Initialize ABI checker.

        Args:
            binary: Binary instance
            abi_spec: Optional ABI specification (auto-detected if None)
        """
        self.binary = binary
        self.abi = abi_spec or detect_abi(binary)
        self.violations: list[ABIViolation] = []

    def check_stack_alignment(self, function_address: int) -> list[ABIViolation]:
        """
        Check that stack alignment is correct at call sites.

        For x86_64 System V and Windows, the stack must be 16-byte aligned
        before a CALL instruction.

        Args:
            function_address: Function address to check

        Returns:
            List of stack alignment violations
        """
        violations: list[ABIViolation] = []

        if self.abi.stack_alignment <= 1:
            return violations

        try:
            instructions = self.binary.get_function_disasm(function_address)
        except Exception as e:
            logger.debug(f"Failed to get disasm for function @ 0x{function_address:x}: {e}")
            return violations

        stack_delta = 0
        for insn in instructions:
            addr = insn.get("offset", insn.get("addr", 0))
            disasm = insn.get("disasm", "").lower()
            mnemonic = disasm.split()[0] if disasm else ""

            if mnemonic in ("push", "pushf", "pushfq", "pushfw"):
                stack_delta -= 8 if self.abi.abi_type in (ABIType.X86_64_SYSTEM_V, ABIType.X86_64_WINDOWS) else 4
            elif mnemonic in ("pop", "popf", "popfq", "popfw"):
                stack_delta += 8 if self.abi.abi_type in (ABIType.X86_64_SYSTEM_V, ABIType.X86_64_WINDOWS) else 4
            elif mnemonic in ("sub", "add") and ("rsp" in disasm or "esp" in disasm or "sp" in disasm):
                parts = disasm.replace(",", " ").split()
                for i, part in enumerate(parts):
                    if part in ("sub", "add") and i + 2 < len(parts):
                        try:
                            imm = int(parts[i + 2].strip(","), 0)
                            if mnemonic == "sub":
                                stack_delta -= imm
                            else:
                                stack_delta += imm
                        except ValueError:
                            pass
            elif mnemonic in ("call", "callq"):
                alignment = self.abi.stack_alignment
                misaligned = stack_delta % alignment

                if misaligned != 0:
                    violations.append(
                        ABIViolation(
                            violation_type=ABIViolationType.STACK_ALIGNMENT,
                            description=f"Stack misaligned by {misaligned} bytes at call (expected {alignment}-byte alignment)",
                            location=addr,
                            details={
                                "alignment": alignment,
                                "misalignment": misaligned,
                                "stack_delta": stack_delta,
                            },
                        )
                    )

            elif mnemonic in ("ret", "retn", "retq", "retl"):
                expected_delta = 0
                if self.abi.abi_type in (ABIType.X86_64_SYSTEM_V, ABIType.X86_64_WINDOWS):
                    if stack_delta != expected_delta:
                        logger.debug(f"Stack imbalance at return: delta={stack_delta} (expected {expected_delta})")

        return violations

    def check_red_zone(self, function_address: int, mutation_regions: list[tuple[int, int]]) -> list[ABIViolation]:
        """
        Check that mutations don't clobber the red zone.

        The red zone is a 128-byte area below RSP on x86_64 System V ABI.
        Leaf functions can use this without adjusting RSP.

        Args:
            function_address: Function address
            mutation_regions: List of (start_address, end_address) tuples for mutated regions

        Returns:
            List of red zone violations
        """
        violations: list[ABIViolation] = []

        if self.abi.red_zone_size <= 0:
            return violations

        if self.abi.abi_type != ABIType.X86_64_SYSTEM_V:
            return violations

        try:
            instructions = self.binary.get_function_disasm(function_address)
        except Exception:
            return violations

        has_call = False
        for insn in instructions:
            disasm = insn.get("disasm", "").lower()
            if disasm.startswith("call"):
                has_call = True
                break

        if has_call:
            return violations

        for start_addr, end_addr in mutation_regions:
            region_size = end_addr - start_addr

            if region_size > self.abi.red_zone_size:
                violations.append(
                    ABIViolation(
                        violation_type=ABIViolationType.RED_ZONE_CLOBBER,
                        description=f"Mutation region ({region_size} bytes) exceeds red zone ({self.abi.red_zone_size} bytes) in leaf function",
                        location=function_address,
                        details={
                            "red_zone_size": self.abi.red_zone_size,
                            "region_size": region_size,
                            "region_start": hex(start_addr),
                            "region_end": hex(end_addr),
                        },
                    )
                )

        return violations

    def check_shadow_space(self, function_address: int) -> list[ABIViolation]:
        """
        Check that shadow space is properly maintained on Windows x64.

        Windows x64 ABI requires 32 bytes of shadow space on the stack
        for the 4 register arguments.

        Args:
            function_address: Function address to check

        Returns:
            List of shadow space violations
        """
        violations: list[ABIViolation] = []

        if self.abi.shadow_space_size <= 0:
            return violations

        if self.abi.abi_type != ABIType.X86_64_WINDOWS:
            return violations

        try:
            instructions = self.binary.get_function_disasm(function_address)
        except Exception:
            return violations

        for i, insn in enumerate(instructions):
            addr = insn.get("offset", insn.get("addr", 0))
            disasm = insn.get("disasm", "").lower()
            mnemonic = disasm.split()[0] if disasm else ""

            if mnemonic in ("call", "callq"):
                found_shadow = False
                for prev_insn in instructions[max(0, i - 5) : i]:
                    prev_disasm = prev_insn.get("disasm", "").lower()
                    if "sub" in prev_disasm and "rsp" in prev_disasm:
                        parts = prev_disasm.replace(",", " ").split()
                        for part in parts:
                            try:
                                val = int(part.strip(","), 0)
                                if val >= self.abi.shadow_space_size:
                                    found_shadow = True
                                    break
                            except ValueError:
                                pass

                    if "push" in prev_disasm:
                        found_shadow = True
                        break

                if not found_shadow:
                    violations.append(
                        ABIViolation(
                            violation_type=ABIViolationType.SHADOW_SPACE_VIOLATION,
                            description=f"Call without proper shadow space allocation ({self.abi.shadow_space_size} bytes required)",
                            location=addr,
                            details={
                                "shadow_space_size": self.abi.shadow_space_size,
                            },
                        )
                    )

        return violations

    def check_callee_saved(self, function_address: int) -> list[ABIViolation]:
        """
        Check that callee-saved registers are preserved.

        Args:
            function_address: Function address

        Returns:
            List of callee-saved register violations
        """
        violations: list[ABIViolation] = []

        if not self.abi.callee_saved_regs:
            return violations

        try:
            instructions = self.binary.get_function_disasm(function_address)
        except Exception:
            return violations

        saved_regs: set[str] = set()
        restored_regs: set[str] = set()
        modified_regs: set[str] = set()

        for insn in instructions[:15]:
            disasm = insn.get("disasm", "").lower()
            parts = disasm.replace(",", " ").split()
            if len(parts) >= 2 and parts[0] in ("push", "pushf", "pushfq"):
                reg = parts[1].rstrip(",")
                if reg in self.abi.callee_saved_regs:
                    saved_regs.add(reg)

        for insn in reversed(instructions[-15:]):
            disasm = insn.get("disasm", "").lower()
            parts = disasm.replace(",", " ").split()
            if len(parts) >= 2 and parts[0] in ("pop", "popf", "popfq"):
                reg = parts[1].rstrip(",")
                if reg in self.abi.callee_saved_regs:
                    restored_regs.add(reg)

        for insn in instructions:
            disasm = insn.get("disasm", "").lower()
            parts = disasm.replace(",", " ").split()
            if len(parts) >= 2:
                mnemonic = parts[0]
                if mnemonic in ("mov", "add", "sub", "xor", "or", "and", "lea", "inc", "dec"):
                    dest = parts[1].rstrip(",")
                    if dest in self.abi.callee_saved_regs and dest not in saved_regs:
                        modified_regs.add(dest)

        for reg in modified_regs:
            if reg not in saved_regs and reg not in restored_regs:
                violations.append(
                    ABIViolation(
                        violation_type=ABIViolationType.CALLEE_SAVED_CLOBBER,
                        description=f"Callee-saved register {reg} modified without save/restore",
                        location=function_address,
                        details={
                            "register": reg,
                            "saved": reg in saved_regs,
                            "restored": reg in restored_regs,
                        },
                    )
                )

        return violations

    def check_all(
        self, function_address: int, mutation_regions: list[tuple[int, int]] | None = None
    ) -> list[ABIViolation]:
        """
        Run all ABI checks for a function.

        Args:
            function_address: Function address
            mutation_regions: Optional list of mutated regions for red zone check

        Returns:
            List of all ABI violations
        """
        violations: list[ABIViolation] = []

        violations.extend(self.check_stack_alignment(function_address))
        violations.extend(self.check_callee_saved(function_address))
        violations.extend(self.check_shadow_space(function_address))

        if mutation_regions:
            violations.extend(self.check_red_zone(function_address, mutation_regions))

        self.violations = violations

        if violations:
            logger.warning(f"Found {len(violations)} ABI violations in function @ 0x{function_address:x}")
            for v in violations:
                logger.debug(f"  {v}")

        return violations

    def validate_mutation(
        self,
        function_address: int,
        original_violations: list[ABIViolation] | None = None,
        mutation_regions: list[tuple[int, int]] | None = None,
    ) -> dict[str, Any]:
        """
        Validate that a mutation doesn't introduce new ABI violations.

        Args:
            function_address: Function address
            original_violations: Violations present before mutation
            mutation_regions: Regions affected by mutation

        Returns:
            Dictionary with validation results
        """
        current_violations = self.check_all(function_address, mutation_regions)

        if original_violations is None:
            return {
                "valid": len(current_violations) == 0,
                "violations": current_violations,
                "new_violations": [],
                "violation_count": len(current_violations),
            }

        new_violations = []
        original_set = {(v.violation_type, v.location) for v in original_violations}

        for violation in current_violations:
            key = (violation.violation_type, violation.location)
            if key not in original_set:
                new_violations.append(violation)

        return {
            "valid": len(new_violations) == 0,
            "violations": current_violations,
            "new_violations": new_violations,
            "violation_count": len(current_violations),
            "new_violation_count": len(new_violations),
        }
