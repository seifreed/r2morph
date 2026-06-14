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
from typing import Any

from r2morph.analysis.abi_detection import detect_abi
from r2morph.analysis.abi_models import ABI_SPECS as _ABI_SPECS
from r2morph.analysis.abi_models import ABISpec, ABIType, ABIViolation, ABIViolationType
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)

ABI_SPECS = _ABI_SPECS


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
                            # Not a parseable numeric literal here (e.g. register/symbolic operand); expected, so this candidate is skipped.
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
                                # Not a parseable numeric literal here (e.g. register/symbolic operand); expected, so this candidate is skipped.
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
