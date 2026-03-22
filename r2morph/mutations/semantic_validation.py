"""
Semantic validation for post-mutation verification.

Validates that mutations preserve program semantics:
- Register preservation verification
- Stack balance checking
- Control flow preservation
- Side effect analysis
"""

from dataclasses import dataclass, field
from typing import Any
from enum import Enum


class ValidationSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    code: str
    severity: ValidationSeverity
    message: str
    address: int = 0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == ValidationSeverity.WARNING]

    def add_error(self, code: str, message: str, address: int = 0, **details: Any) -> None:
        self.issues.append(ValidationIssue(code, ValidationSeverity.ERROR, message, address, details))
        self.valid = False

    def add_warning(self, code: str, message: str, address: int = 0, **details: Any) -> None:
        self.issues.append(ValidationIssue(code, ValidationSeverity.WARNING, message, address, details))


class SemanticValidator:
    """
    Validates semantic preservation after mutations.

    Checks:
    - Register preservation (push/pop balance)
    - Stack balance (no stack leaks)
    - Control flow integrity
    - Side effect analysis
    """

    PRESERVED_REGISTERS_64 = ["rbx", "rbp", "r12", "r13", "r14", "r15"]
    SCRATCH_REGISTERS_64 = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
    ALL_REGISTERS_64 = PRESERVED_REGISTERS_64 + SCRATCH_REGISTERS_64

    PUSH_OPCODES = {"push", "pushq", "pushl", "pushw"}
    POP_OPCODES = {"pop", "popq", "popl", "popw"}
    CONTROL_FLOW_OPCODES = {
        "jmp",
        "je",
        "jne",
        "jz",
        "jnz",
        "jg",
        "jl",
        "jge",
        "jle",
        "ja",
        "jb",
        "jae",
        "jbe",
        "call",
        "ret",
        "retn",
    }
    UNSAFE_OPCODES = {"syscall", "int", "int3", "ud2", "hlt", "cli", "sti"}

    def __init__(self, arch: str = "x86_64"):
        self.arch = arch
        self._register_sizes = {
            "x86_64": 64,
            "x86": 32,
            "arm64": 64,
            "arm": 32,
        }

    def validate_basic_block(
        self,
        instructions: list[dict[str, Any]],
        preserve_registers: bool = True,
        check_control_flow: bool = True,
    ) -> ValidationResult:
        """
        Validate a basic block for semantic preservation.

        Args:
            instructions: List of instruction dicts
            preserve_registers: Check register preservation
            check_control_flow: Check control flow integrity

        Returns:
            ValidationResult with issues
        """
        result = ValidationResult(valid=True)

        if not instructions:
            return result

        stack_depth = 0
        push_pop_pairs: list[tuple[int, str, int]] = []
        preserved_touched: set[str] = set()

        last_address = 0
        for idx, ins in enumerate(instructions):
            mnemonic = self._get_mnemonic(ins)
            address = self._get_address(ins)
            last_address = address

            if mnemonic in self.PUSH_OPCODES:
                op = self._get_operand(ins, 0)
                stack_depth += 1
                push_pop_pairs.append((idx + 1, op if op else "", 0))
            elif mnemonic in self.POP_OPCODES:
                op = self._get_operand(ins, 0)
                stack_depth -= 1
                if stack_depth < 0:
                    result.add_error(
                        "STACK_UNDERFLOW",
                        f"Stack underflow: pop {op} without matching push",
                        address,
                    )
                elif push_pop_pairs:
                    push_pop_pairs[-1] = (push_pop_pairs[-1][0], push_pop_pairs[-1][1], idx + 1)

            if preserve_registers:
                op = self._get_operand(ins, 0)
                if op and isinstance(op, str) and op.lower() in self.PRESERVED_REGISTERS_64:
                    if mnemonic not in (*self.PUSH_OPCODES, *self.POP_OPCODES, "mov"):
                        if mnemonic in ["add", "sub", "xor", "and", "or", "inc", "dec", "shl", "shr", "lea"]:
                            preserved_touched.add(op.lower())

        if stack_depth != 0:
            result.add_error(
                "STACK_UNBALANCED",
                f"Stack not balanced: {stack_depth} items remaining",
                last_address,
            )

        if check_control_flow:
            result = self._validate_control_flow(instructions, result)

        result.metadata["stack_depth"] = stack_depth
        result.metadata["push_pop_pairs"] = push_pop_pairs
        result.metadata["preserved_touched"] = list(preserved_touched)

        return result

    def validate_function(
        self,
        instructions: list[dict[str, Any]],
        abi: str = "systemv",
    ) -> ValidationResult:
        """
        Validate a function for ABI compliance and semantic preservation.

        Args:
            instructions: Function instructions
            abi: ABI (systemv, windows)

        Returns:
            ValidationResult
        """
        result = ValidationResult(valid=True)

        if not instructions:
            return result

        abi_preserved = {
            "systemv": self.PRESERVED_REGISTERS_64,
            "windows": ["rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15"],
        }

        preserved = abi_preserved.get(abi, self.PRESERVED_REGISTERS_64)

        saved_registers: set[str] = set()
        restored_registers: set[str] = set()
        stack_adjustments: list[int] = []

        prologue_end = 0
        epilogue_start = len(instructions)

        for idx, ins in enumerate(instructions):
            mnemonic = self._get_mnemonic(ins)
            op = self._get_operand(ins, 0)

            if mnemonic in self.PUSH_OPCODES and isinstance(op, str) and op.lower() in preserved:
                saved_registers.add(op.lower())
                prologue_end = max(prologue_end, idx + 1)

            if mnemonic in ("sub", "add") and isinstance(op, str) and "rsp" in op.lower():
                try:
                    imm = int(self._get_operand(ins, 1) or "0", 0)
                    if mnemonic == "sub":
                        stack_adjustments.append(imm)
                    else:
                        stack_adjustments.append(-imm)
                except (ValueError, TypeError):
                    pass

        for idx in range(len(instructions) - 1, -1, -1):
            ins = instructions[idx]
            mnemonic = self._get_mnemonic(ins)
            op = self._get_operand(ins, 0)

            if mnemonic in self.POP_OPCODES and isinstance(op, str) and op.lower() in preserved:
                restored_registers.add(op.lower())
                epilogue_start = min(epilogue_start, idx)

        for reg in saved_registers:
            if reg not in restored_registers:
                result.add_error(
                    "REGISTER_NOT_RESTORED",
                    f"Preserved register {reg} saved but not restored",
                    self._get_address(instructions[0]),
                    register=reg,
                )

        for reg in restored_registers:
            if reg not in saved_registers:
                result.add_warning(
                    "REGISTER_UNEXPECTED_RESTORE",
                    f"Register {reg} restored but not saved",
                    self._get_address(instructions[-1]),
                    register=reg,
                )

        result.metadata["saved_registers"] = list(saved_registers)
        result.metadata["restored_registers"] = list(restored_registers)
        result.metadata["prologue_end"] = prologue_end
        result.metadata["epilogue_start"] = epilogue_start

        return result

    def validate_mutation(
        self,
        original_instructions: list[dict[str, Any]],
        mutated_instructions: list[dict[str, Any]],
        mutation_type: str = "substitution",
    ) -> ValidationResult:
        """
        Validate that a mutation preserves semantics.

        Args:
            original_instructions: Original instructions
            mutated_instructions: Mutated instructions
            mutation_type: Type of mutation (substitution, insertion, deletion)

        Returns:
            ValidationResult
        """
        result = ValidationResult(valid=True)

        orig_result = self.validate_basic_block(original_instructions)
        mut_result = self.validate_basic_block(mutated_instructions)

        if orig_result.metadata.get("stack_depth", 0) != mut_result.metadata.get("stack_depth", 0):
            result.add_error(
                "STACK_DEPTH_MISMATCH",
                f"Stack depth changed from {orig_result.metadata.get('stack_depth', 0)} to {mut_result.metadata.get('stack_depth', 0)}",
                0,
                original_depth=orig_result.metadata.get("stack_depth", 0),
                mutated_depth=mut_result.metadata.get("stack_depth", 0),
            )

        orig_pushes = sum(1 for i in original_instructions if self._get_mnemonic(i) in self.PUSH_OPCODES)
        mut_pushes = sum(1 for i in mutated_instructions if self._get_mnemonic(i) in self.PUSH_OPCODES)
        orig_pops = sum(1 for i in original_instructions if self._get_mnemonic(i) in self.POP_OPCODES)
        mut_pops = sum(1 for i in mutated_instructions if self._get_mnemonic(i) in self.POP_OPCODES)

        if (orig_pushes - orig_pops) != (mut_pushes - mut_pops):
            result.add_error(
                "PUSH_POP_IMBALANCE",
                f"Push/pop balance changed: {orig_pushes - orig_pops} -> {mut_pushes - mut_pops}",
                0,
            )

        for idx, ins in enumerate(mutated_instructions):
            mnemonic = self._get_mnemonic(ins)
            if mnemonic in self.UNSAFE_OPCODES:
                result.add_warning(
                    "UNSAFE_OPCODE",
                    f"Unsafe opcode {mnemonic} may affect semantics",
                    self._get_address(ins),
                    mnemonic=mnemonic,
                )

        result.metadata["original_valid"] = orig_result.valid
        result.metadata["mutated_valid"] = mut_result.valid

        return result

    def validate_junk_code(
        self,
        junk_instructions: list[dict[str, Any]],
    ) -> ValidationResult:
        """
        Validate that junk code is semantically neutral.

        Args:
            junk_instructions: Junk code instructions

        Returns:
            ValidationResult
        """
        result = ValidationResult(valid=True)

        if not junk_instructions:
            return result

        registers_written: set[str] = set()
        registers_read: set[str] = set()
        has_unsafe: bool = False

        for idx, ins in enumerate(junk_instructions):
            mnemonic = self._get_mnemonic(ins)
            address = self._get_address(ins)

            if mnemonic in self.UNSAFE_OPCODES:
                has_unsafe = True
                result.add_error(
                    "JUNK_UNSAFE_OPCODE",
                    f"Junk code contains unsafe opcode: {mnemonic}",
                    address,
                    mnemonic=mnemonic,
                )

            op1 = self._get_operand(ins, 0)
            op2 = self._get_operand(ins, 1)
            op3 = self._get_operand(ins, 2)

            for op in [op1, op2, op3]:
                if isinstance(op, str):
                    op_lower = op.lower().strip("[]")
                    if op_lower in self.ALL_REGISTERS_64:
                        if op.startswith("["):
                            pass
                        elif mnemonic in (
                            "mov",
                            "lea",
                            "pop",
                            "inc",
                            "dec",
                            "add",
                            "sub",
                            "xor",
                            "and",
                            "or",
                            "shl",
                            "shr",
                            "rol",
                            "ror",
                        ):
                            if op == op1:
                                registers_written.add(op_lower)
                            else:
                                registers_read.add(op_lower)
                        elif mnemonic in self.PUSH_OPCODES:
                            pass
                        elif mnemonic in self.POP_OPCODES:
                            pass

            if mnemonic in ("mov", "lea", "add", "sub", "xor", "and", "or", "cmp", "test"):
                for op in [op2, op3]:
                    if isinstance(op, str) and "[" in op:
                        result.add_warning(
                            "JUNK_MEMORY_ACCESS",
                            f"Junk code accesses memory: {mnemonic}",
                            address,
                        )

        if has_unsafe:
            result.valid = False

        result.metadata["registers_written"] = list(registers_written)
        result.metadata["registers_read"] = list(registers_read)

        return result

    def _validate_control_flow(
        self,
        instructions: list[dict[str, Any]],
        result: ValidationResult,
    ) -> ValidationResult:
        """Validate control flow integrity."""

        for idx, ins in enumerate(instructions):
            mnemonic = self._get_mnemonic(ins)
            address = self._get_address(ins)

            if mnemonic in self.CONTROL_FLOW_OPCODES:
                target = self._get_jump_target(ins)
                if target is not None:
                    valid_targets = set(self._get_address(i) for i in instructions)
                    if isinstance(target, int) and target not in valid_targets:
                        result.add_warning(
                            "JUMP_EXTERNAL",
                            f"{mnemonic} to external address 0x{target:x}",
                            address,
                            target=target,
                        )

        return result

    def _get_mnemonic(self, ins: dict[str, Any]) -> str:
        return (ins.get("mnemonic") or ins.get("type") or "").lower()

    def _get_address(self, ins: dict[str, Any]) -> int:
        addr = ins.get("addr", ins.get("address", 0))
        return int(addr, 0) if isinstance(addr, str) else addr

    def _get_operand(self, ins: dict[str, Any], idx: int) -> str | None:
        ops = ins.get("operands", [])
        if isinstance(ops, dict):
            return ops.get(str(idx)) or ops.get(idx)
        elif isinstance(ops, list) and idx < len(ops):
            result = ops[idx]
            return str(result) if result is not None else None
        op_key = f"operand_{idx + 1}"
        result = ins.get(op_key)
        return str(result) if result is not None else None

    def _get_jump_target(self, ins: dict[str, Any]) -> int | None:
        jump = ins.get("jump") or ins.get("target")
        if jump:
            try:
                return int(jump, 0) if isinstance(jump, str) else jump
            except (ValueError, TypeError):
                pass
        return None


def create_validator(arch: str = "x86_64") -> SemanticValidator:
    """Factory function to create a SemanticValidator."""
    return SemanticValidator(arch)


__all__ = [
    "SemanticValidator",
    "ValidationResult",
    "ValidationIssue",
    "ValidationSeverity",
    "create_validator",
]
