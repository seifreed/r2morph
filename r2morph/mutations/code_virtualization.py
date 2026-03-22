"""
Code Virtualization - Transform code to custom VM bytecode.

Translates native code instructions into bytecode for a custom
virtual machine, making reverse engineering significantly harder
by obscuring the actual operations performed.

This is similar to techniques used by VMProtect, Themida,
and other commercial obfuscators.

Example transformation:

    Original:
        mov eax, 1
        add eax, 5
        ret

    Virtualized:
        push 0x0003        ; VM_EXIT
        push 0x0005        ; operand 5
        push 0x0001        ; ADD opcode
        push 0x0001        ; operand 1
        push 0x0000        ; MOV opcode
        call vm_execute    ; run VM

    The VM interprets these opcodes, performing the operations
    without exposing the actual native instructions.

VM Architecture:
    - Stack-based VM with operand stack
    - Handler table for each opcode
    - Context registers (vreg0-vreg7 map to real registers)
    - Control flow through opcode dispatch

Opcode Categories:
    - Data movement: MOV, PUSH, POP
    - Arithmetic: ADD, SUB, MUL, DIV, INC, DEC
    - Logic: AND, OR, XOR, NOT
    - Control flow: JMP, JZ, JNZ, CALL, RET
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

if TYPE_CHECKING:
    pass
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


class VMOpcode(IntEnum):
    """Virtual machine opcodes."""

    NOP = 0x00

    MOV_REG_REG = 0x01
    MOV_REG_IMM = 0x02
    MOV_REG_MEM = 0x03
    MOV_MEM_REG = 0x04

    PUSH_REG = 0x10
    PUSH_IMM = 0x11
    POP_REG = 0x12

    ADD_REG_REG = 0x20
    ADD_REG_IMM = 0x21
    SUB_REG_REG = 0x22
    SUB_REG_IMM = 0x23
    MUL_REG_REG = 0x24
    DIV_REG_REG = 0x25
    INC_REG = 0x26
    DEC_REG = 0x27

    AND_REG_REG = 0x30
    AND_REG_IMM = 0x31
    OR_REG_REG = 0x32
    OR_REG_IMM = 0x33
    XOR_REG_REG = 0x34
    XOR_REG_IMM = 0x35
    NOT_REG = 0x36
    SHL_REG_IMM = 0x37
    SHR_REG_IMM = 0x38

    CMP_REG_REG = 0x40
    CMP_REG_IMM = 0x41
    TEST_REG_REG = 0x42
    TEST_REG_IMM = 0x43

    JMP = 0x50
    JZ = 0x51
    JNZ = 0x52
    JG = 0x53
    JL = 0x54
    JGE = 0x55
    JLE = 0x56
    CALL = 0x57
    RET = 0x58

    LEA_REG_MEM = 0x60

    XCHG_REG_REG = 0x70

    VM_ENTER = 0xF0
    VM_EXIT = 0xF1
    VM_NOP = 0xF2
    VM_SWAP = 0xF3
    VM_DUP = 0xF4

    UNKNOWN = 0xFF


class VMHandler(IntEnum):
    """Handler types for each opcode."""

    NOP = 0

    MOV = 1
    ADD = 2
    SUB = 3
    MUL = 4
    DIV = 5
    AND = 6
    OR = 7
    XOR = 8
    NOT = 9
    SHL = 10
    SHR = 11

    PUSH = 20
    POP = 21

    CMP = 30
    TEST = 31

    JMP = 40
    JCC = 41
    CALL = 42
    RET = 43

    LEA = 50
    XCHG = 51


@dataclass
class VMInstruction:
    """Virtual machine instruction."""

    opcode: VMOpcode
    operands: list[int | str] = field(default_factory=list)
    original_asm: str = ""
    bytecode_offset: int = 0

    def to_bytecode(self) -> bytes:
        """Convert instruction to bytecode."""
        result = bytes([self.opcode])
        for op in self.operands:
            if isinstance(op, int):
                if -128 <= op <= 127:
                    result += op.to_bytes(1, "little", signed=True)
                elif -32768 <= op <= 32767:
                    result += op.to_bytes(2, "little", signed=True)
                else:
                    result += op.to_bytes(4, "little", signed=True)
            elif isinstance(op, str):
                result += op.encode("utf-8") + b"\x00"
        return result


@dataclass
class VMContext:
    """Virtual machine context for execution simulation."""

    registers: dict[str, int] = field(default_factory=lambda: {})
    stack: list[int] = field(default_factory=list)
    flags: dict[str, bool] = field(
        default_factory=lambda: {
            "ZF": False,
            "SF": False,
            "CF": False,
            "OF": False,
        }
    )
    pc: int = 0
    running: bool = True


REG_MAP_X64 = {
    "rax": 0,
    "rcx": 1,
    "rdx": 2,
    "rbx": 3,
    "rsp": 4,
    "rbp": 5,
    "rsi": 6,
    "rdi": 7,
    "r8": 8,
    "r9": 9,
    "r10": 10,
    "r11": 11,
    "r12": 12,
    "r13": 13,
    "r14": 14,
    "r15": 15,
}

REG_MAP_X86 = {
    "eax": 0,
    "ecx": 1,
    "edx": 2,
    "ebx": 3,
    "esp": 4,
    "ebp": 5,
    "esi": 6,
    "edi": 7,
}

CONDITION_CODES = {
    "je": VMOpcode.JZ,
    "jne": VMOpcode.JNZ,
    "jz": VMOpcode.JZ,
    "jnz": VMOpcode.JNZ,
    "jg": VMOpcode.JG,
    "jl": VMOpcode.JL,
    "jge": VMOpcode.JGE,
    "jle": VMOpcode.JLE,
    "ja": VMOpcode.JG,
    "jb": VMOpcode.JL,
    "jae": VMOpcode.JGE,
    "jbe": VMOpcode.JLE,
}


def generate_vm_dispatcher_x64(num_handlers: int = 256) -> str:
    """
    Generate x64 assembly for VM dispatcher.

    Args:
        num_handlers: Number of handler slots

    Returns:
        Assembly code string
    """
    asm = """
; Virtual Machine Dispatcher (x64)
; Executes bytecode from RSI pointer

vm_execute:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Initialize VM context - allocate context area on stack
    sub rsp, 256               ; VM context area (16 registers * 8 bytes + stack)
    mov rbx, rsp               ; VM context base pointer
    mov r12, rsi                ; bytecode pointer
    mov r13, 0                  ; stack pointer (virtual stack)

.vm_loop:
    movzx eax, byte [r12]      ; load opcode
    inc r12                     ; advance PC

    ; Handler table dispatch
    lea rcx, [rel vm_handlers]
    movzx eax, al
    jmp [rcx + rax * 8]         ; jump to handler

.vm_handlers:
"""
    for i in range(num_handlers):
        asm += f"    dq vm_handler_{i:02x}\n"

    return asm


def generate_vm_dispatcher_x86(num_handlers: int = 256) -> str:
    """
    Generate x86 (32-bit) assembly for VM dispatcher.

    Args:
        num_handlers: Number of handler slots

    Returns:
        Assembly code string
    """
    asm = """
; Virtual Machine Dispatcher (x86)
; Executes bytecode from ESI pointer

vm_execute:
    push ebx
    push edi
    push ebp

    ; Initialize VM context - allocate context area on stack
    sub esp, 128               ; VM context area (8 registers * 4 bytes + stack)
    mov ebx, esp               ; VM context base pointer
    mov edi, esi               ; bytecode pointer

.vm_loop:
    movzx eax, byte [edi]     ; load opcode
    inc edi                     ; advance PC

    ; Handler table dispatch
    lea ecx, [vm_handlers]
    movzx eax, al
    jmp [ecx + eax * 4]        ; jump to handler

.vm_handlers:
"""
    for i in range(num_handlers):
        asm += f"    dd vm_handler_{i:02x}\n"

    return asm


def generate_vm_handler_x64(opcode: VMOpcode) -> str:
    """Generate handler code for a specific opcode."""
    handlers = {
        VMOpcode.NOP: """
vm_handler_00:                 ; NOP
    jmp vm_execute
""",
        VMOpcode.MOV_REG_IMM: """
vm_handler_02:                 ; MOV_REG_IMM
    movzx ecx, byte [r12]     ; destination reg
    inc r12
    movsx rax, dword [r12]    ; immediate value
    add r12, 4

    ; Store to virtual register area
    mov [rbx + rcx * 8], rax
    jmp vm_execute
""",
        VMOpcode.ADD_REG_IMM: """
vm_handler_21:                 ; ADD_REG_IMM
    movzx ecx, byte [r12]     ; destination reg
    inc r12
    movsx rax, dword [r12]    ; immediate value
    add r12, 4

    add [rbx + rcx * 8], rax
    jmp vm_execute
""",
        VMOpcode.PUSH_IMM: """
vm_handler_11:                 ; PUSH_IMM
    movsx rax, dword [r12]
    add r12, 4
    push rax
    jmp vm_execute
""",
        VMOpcode.POP_REG: """
vm_handler_12:                 ; POP_REG
    movzx ecx, byte [r12]
    inc r12
    pop rax
    mov [rbx + rcx * 8], rax
    jmp vm_execute
""",
        VMOpcode.JMP: """
vm_handler_50:                 ; JMP
    movsx rax, dword [r12]    ; offset
    add r12, rax              ; relative jump
    jmp vm_execute
""",
        VMOpcode.VM_EXIT: """
vm_handler_f1:                 ; VM_EXIT
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
""",
    }

    return handlers.get(opcode, f"vm_handler_{opcode:02x}: jmp vm_execute\n")


def translate_instruction_to_vm(insn: dict[str, Any], arch: str = "x64") -> VMInstruction | None:
    """
    Translate a native instruction to VM bytecode.

    Args:
        insn: Instruction dictionary with mnemonic and operands
        arch: Architecture ("x64" or "x86")

    Returns:
        VMInstruction or None if not translatable
    """
    mnemonic = insn.get("mnemonic", "").lower()
    op1 = insn.get("op1", "")
    op2 = insn.get("op2", "")
    insn.get("op3", "")

    if mnemonic == "nop":
        return VMInstruction(VMOpcode.NOP, original_asm="nop")

    elif mnemonic == "mov":
        if op1 and op2:
            if op2.lstrip("-").isdigit():
                imm = int(op2)
                return VMInstruction(VMOpcode.MOV_REG_IMM, [op1, imm], f"mov {op1}, {op2}")
            else:
                return VMInstruction(VMOpcode.MOV_REG_REG, [op1, op2], f"mov {op1}, {op2}")

    elif mnemonic == "add":
        if op1 and op2:
            if op2.lstrip("-").isdigit():
                imm = int(op2)
                return VMInstruction(VMOpcode.ADD_REG_IMM, [op1, imm], f"add {op1}, {op2}")
            else:
                return VMInstruction(VMOpcode.ADD_REG_REG, [op1, op2], f"add {op1}, {op2}")

    elif mnemonic == "sub":
        if op1 and op2:
            if op2.lstrip("-").isdigit():
                imm = int(op2)
                return VMInstruction(VMOpcode.SUB_REG_IMM, [op1, imm], f"sub {op1}, {op2}")
            else:
                return VMInstruction(VMOpcode.SUB_REG_REG, [op1, op2], f"sub {op1}, {op2}")

    elif mnemonic == "push":
        if op1:
            if op1.lstrip("-").isdigit():
                imm = int(op1)
                return VMInstruction(VMOpcode.PUSH_IMM, [imm], f"push {op1}")
            else:
                return VMInstruction(VMOpcode.PUSH_REG, [op1], f"push {op1}")

    elif mnemonic == "pop":
        if op1:
            return VMInstruction(VMOpcode.POP_REG, [op1], f"pop {op1}")

    elif mnemonic == "xor":
        if op1 and op2:
            if op1 == op2:
                return VMInstruction(VMOpcode.MOV_REG_IMM, [op1, 0], f"xor {op1}, {op1}")
            elif op2.lstrip("-").isdigit():
                imm = int(op2)
                return VMInstruction(VMOpcode.XOR_REG_IMM, [op1, imm], f"xor {op1}, {op2}")
            else:
                return VMInstruction(VMOpcode.XOR_REG_REG, [op1, op2], f"xor {op1}, {op2}")

    elif mnemonic == "and":
        if op1 and op2:
            if op2.lstrip("-").isdigit():
                imm = int(op2)
                return VMInstruction(VMOpcode.AND_REG_IMM, [op1, imm], f"and {op1}, {op2}")
            else:
                return VMInstruction(VMOpcode.AND_REG_REG, [op1, op2], f"and {op1}, {op2}")

    elif mnemonic == "or":
        if op1 and op2:
            if op2.lstrip("-").isdigit():
                imm = int(op2)
                return VMInstruction(VMOpcode.OR_REG_IMM, [op1, imm], f"or {op1}, {op2}")
            else:
                return VMInstruction(VMOpcode.OR_REG_REG, [op1, op2], f"or {op1}, {op2}")

    elif mnemonic == "inc":
        if op1:
            return VMInstruction(VMOpcode.INC_REG, [op1], f"inc {op1}")

    elif mnemonic == "dec":
        if op1:
            return VMInstruction(VMOpcode.DEC_REG, [op1], f"dec {op1}")

    elif mnemonic == "cmp":
        if op1 and op2:
            if op2.lstrip("-").isdigit():
                imm = int(op2)
                return VMInstruction(VMOpcode.CMP_REG_IMM, [op1, imm], f"cmp {op1}, {op2}")
            else:
                return VMInstruction(VMOpcode.CMP_REG_REG, [op1, op2], f"cmp {op1}, {op2}")

    elif mnemonic == "jmp":
        target = op1 if op1 else "0"
        return VMInstruction(VMOpcode.JMP, [target], f"jmp {target}")

    elif mnemonic in CONDITION_CODES:
        opcode = CONDITION_CODES[mnemonic]
        target = op2 if op2 else op1
        return VMInstruction(opcode, [target], f"{mnemonic} {target}")

    elif mnemonic == "call":
        target = op1 if op1 else "0"
        return VMInstruction(VMOpcode.CALL, [target], f"call {target}")

    elif mnemonic == "ret":
        return VMInstruction(VMOpcode.RET, [], "ret")

    elif mnemonic == "lea":
        if op1 and op2:
            return VMInstruction(VMOpcode.LEA_REG_MEM, [op1, op2], f"lea {op1}, {op2}")

    elif mnemonic == "xchg":
        if op1 and op2:
            return VMInstruction(VMOpcode.XCHG_REG_REG, [op1, op2], f"xchg {op1}, {op2}")

    return None


class CodeVirtualizationPass(MutationPass):
    """
    Mutation pass that virtualizes code into custom VM bytecode.

    Transforms selected functions to run on a virtual machine,
    making reverse engineering much harder.

    Config options:
        - probability: Probability of virtualizing each function (default: 0.3)
        - max_functions: Maximum functions to virtualize (default: 5)
        - include_dispatcher: Include dispatcher in output (default: True)
        - opcode_randomization: Randomize opcode mapping (default: True)
        - junk_handlers: Add junk handlers (default: True)
    """

    SUPPORTED_INSNS = {
        "mov",
        "add",
        "sub",
        "xor",
        "and",
        "or",
        "inc",
        "dec",
        "push",
        "pop",
        "cmp",
        "jmp",
        "call",
        "ret",
        "lea",
        "xchg",
        "nop",
        "jz",
        "jnz",
        "je",
        "jne",
        "jg",
        "jl",
        "jge",
        "jle",
        "test",
        "shl",
        "shr",
    }

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="CodeVirtualization", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.max_functions = self.config.get("max_functions", 5)
        self.include_dispatcher = self.config.get("include_dispatcher", True)
        self.opcode_randomization = self.config.get("opcode_randomization", True)
        self.junk_handlers = self.config.get("junk_handlers", True)
        self.set_support(
            formats=("ELF", "PE"),
            architectures=("x86_64", "x86"),
            validators=("structural",),
            stability="experimental",
            notes=(
                "transforms code to VM bytecode",
                "generates custom dispatcher for each run",
                "opcode mapping can be randomized",
            ),
        )

    def _can_virtualize(self, instructions: list[dict[str, Any]]) -> tuple[bool, str]:
        """Check if instructions can be virtualized."""
        for insn in instructions:
            mnemonic = insn.get("mnemonic", "").lower()

            if mnemonic not in self.SUPPORTED_INSNS:
                return False, f"unsupported instruction: {mnemonic}"

            if insn.get("type") in ("rep", "repz", "repnz"):
                return False, "rep prefix not supported"

            if any(p in insn.get("disasm", "").lower() for p in ["rip", "[rsp", "[rbp"]):
                return False, "rip-relative or stack addressing"

        return True, ""

    def _virtualize_block(self, instructions: list[dict[str, Any]], arch: str) -> list[VMInstruction]:
        """Virtualize a basic block to VM bytecode."""
        vm_insns = []

        vm_insns.append(VMInstruction(VMOpcode.VM_ENTER, [], "vm_enter"))

        for insn in instructions:
            vm_insn = translate_instruction_to_vm(insn, arch)
            if vm_insn:
                vm_insns.append(vm_insn)
            else:
                vm_insns.append(VMInstruction(VMOpcode.VM_NOP, [], f"; skipped: {insn.get('mnemonic', 'unknown')}"))

        vm_insns.append(VMInstruction(VMOpcode.VM_EXIT, [], "vm_exit"))

        return vm_insns

    def _generate_bytecode(self, vm_insns: list[VMInstruction]) -> bytes:
        """Generate bytecode from VM instructions."""
        bytecode = bytearray()

        for vm_insn in vm_insns:
            vm_insn.bytecode_offset = len(bytecode)
            bytecode.extend(vm_insn.to_bytecode())

        return bytes(bytecode)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply code virtualization.

        Args:
            binary: Any to virtualize

        Returns:
            Statistics dictionary
        """
        self._reset_random()
        logger.info("Applying code virtualization")

        functions = binary.get_functions()
        virtualized_count = 0
        skipped_count = 0
        total_insns = 0
        total_bytecode = 0

        arch_info = binary.get_arch_info()
        arch = "x64" if arch_info.get("arch") in ("x86_64", "x64", "amd64") else "x86"

        for func in functions:
            if virtualized_count >= self.max_functions:
                break

            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            if random.random() > self.probability:
                skipped_count += 1
                continue

            try:
                blocks = binary.get_basic_blocks(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get blocks: {e}")
                continue

            for block in blocks:
                try:
                    insns = binary.r2.cmdj(f"pdj {block['size']} @ {block['addr']}")
                except Exception:
                    continue

                if not insns:
                    continue

                can_virt, reason = self._can_virtualize(insns)
                if not can_virt:
                    logger.debug(f"Cannot virtualize: {reason}")
                    continue

                vm_insns = self._virtualize_block(insns, arch)
                bytecode = self._generate_bytecode(vm_insns)

                block_addr = block.get("addr", 0)
                block_size = block.get("size", 0)

                if len(bytecode) <= block_size:
                    mutation_checkpoint = self._create_mutation_checkpoint("virtualize")
                    baseline = {}
                    if self._validation_manager is not None:
                        baseline = self._validation_manager.capture_structural_baseline(binary, func["addr"])

                    original_bytes = binary.read_bytes(block_addr, block_size)

                    if binary.write_bytes(block_addr, bytecode):
                        mutated_bytes = binary.read_bytes(block_addr, block_size)
                        record = self._record_mutation(
                            function_address=func["addr"],
                            start_address=block_addr,
                            end_address=block_addr + block_size - 1,
                            original_bytes=original_bytes if original_bytes else bytecode,
                            mutated_bytes=mutated_bytes if mutated_bytes else bytecode,
                            original_disasm=f"; {len(insns)} instructions virtualized",
                            mutated_disasm=f"; VM bytecode ({len(bytecode)} bytes)",
                            mutation_kind="code_virtualization",
                            metadata={
                                "instructions_count": len(insns),
                                "bytecode_size": len(bytecode),
                                "structural_baseline": baseline,
                            },
                        )
                        if self._validation_manager is not None:
                            outcome = self._validation_manager.validate_mutation(binary, record.to_dict())
                            if not outcome.passed and mutation_checkpoint is not None:
                                if self._session is not None:
                                    self._session.rollback_to(mutation_checkpoint)
                                binary.reload()
                                if self._records:
                                    self._records.pop()
                                if self._rollback_policy == "fail-fast":
                                    raise RuntimeError("Mutation-level validation failed")
                                continue

                        total_insns += len(insns)
                        total_bytecode += len(bytecode)
                        virtualized_count += 1
                        logger.debug(
                            f"Virtualized block at 0x{block_addr:x}: {len(insns)} insns -> {len(bytecode)} bytes bytecode"
                        )

        if self.include_dispatcher and virtualized_count > 0:
            if arch == "x64":
                generate_vm_dispatcher_x64()
            else:
                generate_vm_dispatcher_x86()
            logger.debug("Generated VM dispatcher")

        return {
            "functions_virtualized": virtualized_count,
            "functions_skipped": skipped_count,
            "total_instructions": total_insns,
            "total_bytecode_bytes": total_bytecode,
            "architecture": arch,
            "include_dispatcher": self.include_dispatcher,
        }


class VMProfile:
    """
    A VM profile defines the characteristics of a specific VM configuration.

    Multiple VM profiles can be used to virtualize different functions,
    making analysis significantly harder as reverse engineers must
    understand multiple VM implementations.
    """

    def __init__(
        self,
        name: str,
        opcode_base: int = 0x00,
        handler_style: str = "standard",
        register_mapping: dict[str, int] | None = None,
        stack_layout: str = "grows_down",
        byte_order: str = "little",
        junk_handlers: int = 0,
        obfuscate_handlers: bool = False,
    ):
        self.name = name
        self.opcode_base = opcode_base
        self.handler_style = handler_style
        self.register_mapping = register_mapping or {}
        self.stack_layout = stack_layout
        self.byte_order = byte_order
        self.junk_handlers = junk_handlers
        self.obfuscate_handlers = obfuscate_handlers


MULTI_VM_PROFILES = [
    VMProfile(
        name="simple",
        opcode_base=0x00,
        handler_style="standard",
        register_mapping={"rax": 0, "rcx": 1, "rdx": 2, "rbx": 3},
        junk_handlers=0,
        obfuscate_handlers=False,
    ),
    VMProfile(
        name="obfuscated",
        opcode_base=0x80,
        handler_style="indirect",
        register_mapping={"r8": 0, "r9": 1, "r10": 2, "r11": 3},
        junk_handlers=5,
        obfuscate_handlers=True,
    ),
    VMProfile(
        name="stack_based",
        opcode_base=0xC0,
        handler_style="stack",
        register_mapping={"rsp": 0, "rbp": 1, "rsi": 2, "rdi": 3},
        junk_handlers=10,
        obfuscate_handlers=True,
    ),
    VMProfile(
        name="register_based",
        opcode_base=0x40,
        handler_style="register",
        register_mapping={"r12": 0, "r13": 1, "r14": 2, "r15": 3},
        junk_handlers=15,
        obfuscate_handlers=True,
    ),
]


def generate_multi_vm_dispatcher_x64(profile: VMProfile) -> str:
    """
    Generate a VM dispatcher for a specific profile.

    Each profile produces different dispatcher code, making analysis
    harder when multiple VMs are used.
    """
    dispatcher_label = f"vm_execute_{profile.name}"
    handler_table_label = f"vm_handlers_{profile.name}"

    if profile.handler_style == "indirect":
        prelude = f"""
{dispatcher_label}:
    ; Indirect handler style for {profile.name}
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11

    mov rsi, [rsp + 88]  ; bytecode pointer
    xor rbx, rbx
    lea rcx, [{handler_table_label}]
"""
    elif profile.handler_style == "stack":
        prelude = f"""
{dispatcher_label}:
    ; Stack-based handler style for {profile.name}
    push rbp
    mov rbp, rsp
    sub rsp, 256
    push rax
    push rbx
    push rcx
    push rdx

    mov rsi, [rbp + 8]  ; bytecode pointer
    lea rdi, [rbp - 256]  ; VM stack
"""
    else:
        prelude = f"""
{dispatcher_label}:
    ; Standard dispatcher for {profile.name}
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rsi  ; bytecode pointer
    xor rbx, rbx  ; VM context
"""

    dispatch_loop = f"""
.vm_loop_{profile.name}:
    movzx eax, byte [rsi]
    inc rsi

    ; Dispatch to handler
"""

    if profile.handler_style == "indirect":
        dispatch_loop += f"""
    movzx ecx, al
    mov rax, [rcx + {profile.opcode_base}]
    jmp rax
"""
    else:
        dispatch_loop += f"""
    lea rdx, [{handler_table_label}]
    movzx ecx, al
    jmp [rdx + rcx * 8]
"""

    handlers_section = f"\n{handler_table_label}:\n"
    for i in range(256):
        handlers_section += f"    dq vm_{profile.name}_handler_{i:02x}\n"

    junk_handlers_code = ""
    if profile.junk_handlers > 0:
        junk_handlers_code = f"\n; Junk handlers ({profile.junk_handlers})\n"
        for i in range(profile.junk_handlers):
            junk_handlers_code += f"""vm_{profile.name}_junk_{i}:
    nop
    nop
    jmp .vm_loop_{profile.name}

"""

    return prelude + dispatch_loop + handlers_section + junk_handlers_code


def generate_multi_vm_handler_x64(opcode: int | VMOpcode, profile: VMProfile) -> str:
    """
    Generate a handler for a specific opcode and VM profile.

    Each profile can have different implementations for the same opcode,
    making cross-profiling analysis necessary.
    """
    handler_name = f"vm_{profile.name}_handler_{opcode:02x}"

    opcodes_with_regs = {
        VMOpcode.MOV_REG_IMM: ("mov", "imm"),
        VMOpcode.ADD_REG_IMM: ("add", "imm"),
        VMOpcode.SUB_REG_IMM: ("sub", "imm"),
        VMOpcode.PUSH_IMM: ("push", "imm"),
        VMOpcode.POP_REG: ("pop", "reg"),
    }

    if opcode in [VMOpcode.NOP, VMOpcode.VM_NOP]:
        return f"{handler_name}:\n    nop\n    jmp vm_execute_{profile.name}\n"

    if opcode == VMOpcode.VM_ENTER:
        return f"{handler_name}:\n    ; VM enter\n    jmp vm_execute_{profile.name}\n"

    if opcode == VMOpcode.VM_EXIT:
        if profile.handler_style == "stack":
            return f"""{handler_name}:
    pop rdx
    pop rcx
    pop rbx
    pop rax
    mov rsp, rbp
    pop rbp
    ret
"""
        else:
            return f"""{handler_name}:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
"""

    vm_opcode = VMOpcode(opcode) if not isinstance(opcode, VMOpcode) else opcode
    if vm_opcode in opcodes_with_regs:
        mnemonic, op_type = opcodes_with_regs[vm_opcode]
        if profile.obfuscate_handlers:
            return f"""{handler_name}:
    ; Obfuscated {mnemonic} handler
    movzx ecx, byte [rsi]
    inc rsi
    movsx rax, dword [rsi]
    add rsi, 4
    {mnemonic} [rbx + rcx * 8], rax
    jmp vm_execute_{profile.name}
"""
        else:
            return f"""{handler_name}:
    movzx ecx, byte [rsi]
    inc rsi
    movsx rax, dword [rsi]
    add rsi, 4
    {mnemonic} [rbx + rcx * 8], rax
    jmp vm_execute_{profile.name}
"""

    if opcode == VMOpcode.JMP:
        if profile.handler_style == "indirect":
            return f"""{handler_name}:
    movsx rax, dword [rsi]
    add rsi, rax
    jmp vm_execute_{profile.name}
"""
        else:
            return f"""{handler_name}:
    movsx rax, dword [rsi]
    add rsi, rax
    jmp vm_execute_{profile.name}
"""

    return f"{handler_name}:\n    jmp vm_execute_{profile.name}\n"


class MultiVMVirtualizationPass(CodeVirtualizationPass):
    """
    Enhanced code virtualization using multiple VM profiles.

    Uses different VM configurations for different functions,
    making reverse engineering significantly harder as analysts
    must understand multiple VM implementations.

    Config options:
        - num_vms: Number of VM profiles to use (default: 2)
        - profiles: List of VM profile names to use (default: ["simple", "obfuscated"])
        - randomize_selection: Randomize which VM is used (default: True)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        config["opcode_randomization"] = True
        super().__init__(config=config)
        self.num_vms = self.config.get("num_vms", 2)
        self.profile_names = self.config.get("profiles", ["simple", "obfuscated"])
        self.randomize_selection = self.config.get("randomize_selection", True)
        self.active_profiles: list[VMProfile] = []
        self._init_profiles()

    def _init_profiles(self) -> None:
        """Initialize VM profiles."""
        available = {p.name: p for p in MULTI_VM_PROFILES}
        self.active_profiles = []

        for name in self.profile_names[: self.num_vms]:
            if name in available:
                self.active_profiles.append(available[name])
            else:
                self.active_profiles.append(MULTI_VM_PROFILES[0])

        if not self.active_profiles:
            self.active_profiles = [MULTI_VM_PROFILES[0]]

    def _select_vm_profile(self, func_addr: int) -> VMProfile:
        """Select a VM profile for a function."""
        if self.randomize_selection:
            return random.choice(self.active_profiles)
        return self.active_profiles[func_addr % len(self.active_profiles)]

    def _virtualize_with_profile(
        self, instructions: list[dict[str, Any]], arch: str, profile: VMProfile
    ) -> tuple[list[VMInstruction], bytes]:
        """Virtualize instructions using a specific VM profile."""
        vm_insns = []

        opcode_offset = profile.opcode_base

        vm_insns.append(VMInstruction(VMOpcode.VM_ENTER, [], "vm_enter"))

        for insn in instructions:
            vm_insn = translate_instruction_to_vm(insn, arch)
            if vm_insn:
                adjusted_opcode_value = int(vm_insn.opcode) + opcode_offset
                adjusted_opcode = VMOpcode(adjusted_opcode_value)
                vm_insn_adjusted = VMInstruction(
                    adjusted_opcode,
                    vm_insn.operands,
                    vm_insn.original_asm,
                )
                vm_insns.append(vm_insn_adjusted)
            else:
                vm_insns.append(VMInstruction(VMOpcode.VM_NOP, [], f"; skipped: {insn.get('mnemonic', 'unknown')}"))

        vm_insns.append(VMInstruction(VMOpcode.VM_EXIT, [], "vm_exit"))

        bytecode = bytearray()
        for vm_insn in vm_insns:
            vm_insn.bytecode_offset = len(bytecode)
            bytecode.extend(vm_insn.to_bytecode())

        return vm_insns, bytes(bytecode)

    def apply(self, binary: Any) -> dict[str, Any]:
        """Apply multi-VM virtualization."""
        self._reset_random()
        logger.info(f"Applying multi-VM virtualization with {len(self.active_profiles)} VMs")

        functions = binary.get_functions()
        virtualized_count = 0
        skipped_count = 0
        total_insns = 0
        total_bytecode = 0
        profiles_used: dict[str, int] = {p.name: 0 for p in self.active_profiles}

        arch_info = binary.get_arch_info()
        arch = "x64" if arch_info.get("arch") in ("x86_64", "x64", "amd64") else "x86"

        for func in functions:
            if virtualized_count >= self.max_functions:
                break

            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            if random.random() > self.probability:
                skipped_count += 1
                continue

            try:
                blocks = binary.get_basic_blocks(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get blocks: {e}")
                continue

            profile = self._select_vm_profile(func.get("addr", 0))
            profiles_used[profile.name] += 1

            for block in blocks:
                try:
                    insns = binary.r2.cmdj(f"pdj {block['size']} @ {block['addr']}")
                except Exception:
                    continue

                if not insns:
                    continue

                can_virt, reason = self._can_virtualize(insns)
                if not can_virt:
                    logger.debug(f"Cannot virtualize: {reason}")
                    continue

                vm_insns, bytecode = self._virtualize_with_profile(insns, arch, profile)

                total_insns += len(insns)
                total_bytecode += len(bytecode)
                virtualized_count += 1

                logger.debug(
                    f"Virtualized block at 0x{block['addr']:x} with VM '{profile.name}': "
                    f"{len(insns)} insns -> {len(bytecode)} bytes bytecode"
                )

        dispatchers = {}
        if self.include_dispatcher and virtualized_count > 0:
            for profile in self.active_profiles:
                dispatcher_asm = generate_multi_vm_dispatcher_x64(profile)
                dispatchers[profile.name] = dispatcher_asm
                logger.debug(f"Generated VM dispatcher for '{profile.name}'")

        return {
            "functions_virtualized": virtualized_count,
            "functions_skipped": skipped_count,
            "total_instructions": total_insns,
            "total_bytecode_bytes": total_bytecode,
            "architecture": arch,
            "profiles_used": profiles_used,
            "dispatchers_generated": len(dispatchers),
            "active_profiles": [p.name for p in self.active_profiles],
        }
