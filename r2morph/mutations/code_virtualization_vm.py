"""
VM model and translation helpers for code virtualization.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "VMOpcode",
    "VMHandler",
    "VMInstruction",
    "VMContext",
    "REG_MAP_X64",
    "REG_MAP_X86",
    "CONDITION_CODES",
    "generate_vm_dispatcher_x64",
    "generate_vm_dispatcher_x86",
    "generate_vm_handler_x64",
    "virtualize_block_to_vm_instructions",
    "generate_vm_bytecode",
    "translate_instruction_to_vm",
    "VMProfile",
    "MULTI_VM_PROFILES",
    "generate_multi_vm_dispatcher_x64",
    "generate_multi_vm_handler_x64",
]


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

    registers: dict[str, int] = field(default_factory=dict)
    stack: list[int] = field(default_factory=list)
    flags: dict[str, bool] = field(
        default_factory=lambda: {"ZF": False, "SF": False, "CF": False, "OF": False}
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
    mov r12, rsi               ; bytecode pointer
    mov r13, 0                 ; stack pointer (virtual stack)

.vm_loop:
    movzx eax, byte [r12]      ; load opcode
    inc r12                    ; advance PC

    ; Handler table dispatch
    lea rcx, [rel vm_handlers]
    movzx eax, al
    jmp [rcx + rax * 8]        ; jump to handler

.vm_handlers:
"""
    for i in range(num_handlers):
        asm += f"    dq vm_handler_{i:02x}\n"
    return asm


def generate_vm_dispatcher_x86(num_handlers: int = 256) -> str:
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
    movzx eax, byte [edi]      ; load opcode
    inc edi                    ; advance PC

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


def virtualize_block_to_vm_instructions(
    instructions: list[dict[str, Any]], arch: str
) -> list[VMInstruction]:
    vm_insns: list[VMInstruction] = [VMInstruction(VMOpcode.VM_ENTER, [], "vm_enter")]

    for insn in instructions:
        vm_insn = translate_instruction_to_vm(insn, arch)
        if vm_insn:
            vm_insns.append(vm_insn)
        else:
            vm_insns.append(VMInstruction(VMOpcode.VM_NOP, [], f"; skipped: {insn.get('mnemonic', 'unknown')}"))

    vm_insns.append(VMInstruction(VMOpcode.VM_EXIT, [], "vm_exit"))
    return vm_insns


def generate_vm_bytecode(vm_insns: list[VMInstruction]) -> bytes:
    bytecode = bytearray()
    for vm_insn in vm_insns:
        vm_insn.bytecode_offset = len(bytecode)
        bytecode.extend(vm_insn.to_bytecode())
    return bytes(bytecode)


def _translate_instruction_to_vm(insn: dict[str, Any], arch: str = "x64") -> VMInstruction | None:
    mnemonic = insn.get("mnemonic", "").lower()
    op1 = insn.get("op1", "")
    op2 = insn.get("op2", "")
    insn.get("op3", "")

    if mnemonic == "nop":
        return VMInstruction(VMOpcode.NOP, original_asm="nop")
    if mnemonic == "mov" and op1 and op2:
        if op2.lstrip("-").isdigit():
            return VMInstruction(VMOpcode.MOV_REG_IMM, [op1, int(op2)], f"mov {op1}, {op2}")
        return VMInstruction(VMOpcode.MOV_REG_REG, [op1, op2], f"mov {op1}, {op2}")
    if mnemonic == "add" and op1 and op2:
        if op2.lstrip("-").isdigit():
            return VMInstruction(VMOpcode.ADD_REG_IMM, [op1, int(op2)], f"add {op1}, {op2}")
        return VMInstruction(VMOpcode.ADD_REG_REG, [op1, op2], f"add {op1}, {op2}")
    if mnemonic == "sub" and op1 and op2:
        if op2.lstrip("-").isdigit():
            return VMInstruction(VMOpcode.SUB_REG_IMM, [op1, int(op2)], f"sub {op1}, {op2}")
        return VMInstruction(VMOpcode.SUB_REG_REG, [op1, op2], f"sub {op1}, {op2}")
    if mnemonic == "push" and op1:
        if op1.lstrip("-").isdigit():
            return VMInstruction(VMOpcode.PUSH_IMM, [int(op1)], f"push {op1}")
        return VMInstruction(VMOpcode.PUSH_REG, [op1], f"push {op1}")
    if mnemonic == "pop" and op1:
        return VMInstruction(VMOpcode.POP_REG, [op1], f"pop {op1}")
    if mnemonic == "xor" and op1 and op2:
        if op1 == op2:
            return VMInstruction(VMOpcode.MOV_REG_IMM, [op1, 0], f"xor {op1}, {op1}")
        if op2.lstrip("-").isdigit():
            return VMInstruction(VMOpcode.XOR_REG_IMM, [op1, int(op2)], f"xor {op1}, {op2}")
        return VMInstruction(VMOpcode.XOR_REG_REG, [op1, op2], f"xor {op1}, {op2}")
    if mnemonic == "and" and op1 and op2:
        if op2.lstrip("-").isdigit():
            return VMInstruction(VMOpcode.AND_REG_IMM, [op1, int(op2)], f"and {op1}, {op2}")
        return VMInstruction(VMOpcode.AND_REG_REG, [op1, op2], f"and {op1}, {op2}")
    if mnemonic == "or" and op1 and op2:
        if op2.lstrip("-").isdigit():
            return VMInstruction(VMOpcode.OR_REG_IMM, [op1, int(op2)], f"or {op1}, {op2}")
        return VMInstruction(VMOpcode.OR_REG_REG, [op1, op2], f"or {op1}, {op2}")
    if mnemonic == "inc" and op1:
        return VMInstruction(VMOpcode.INC_REG, [op1], f"inc {op1}")
    if mnemonic == "dec" and op1:
        return VMInstruction(VMOpcode.DEC_REG, [op1], f"dec {op1}")
    if mnemonic == "cmp" and op1 and op2:
        if op2.lstrip("-").isdigit():
            return VMInstruction(VMOpcode.CMP_REG_IMM, [op1, int(op2)], f"cmp {op1}, {op2}")
        return VMInstruction(VMOpcode.CMP_REG_REG, [op1, op2], f"cmp {op1}, {op2}")
    if mnemonic == "jmp":
        target = op1 or "0"
        return VMInstruction(VMOpcode.JMP, [target], f"jmp {target}")
    if mnemonic in CONDITION_CODES:
        target = op2 or op1
        return VMInstruction(CONDITION_CODES[mnemonic], [target], f"{mnemonic} {target}")
    if mnemonic == "call":
        target = op1 or "0"
        return VMInstruction(VMOpcode.CALL, [target], f"call {target}")
    if mnemonic == "ret":
        return VMInstruction(VMOpcode.RET, [], "ret")
    if mnemonic == "lea" and op1 and op2:
        return VMInstruction(VMOpcode.LEA_REG_MEM, [op1, op2], f"lea {op1}, {op2}")
    if mnemonic == "xchg" and op1 and op2:
        return VMInstruction(VMOpcode.XCHG_REG_REG, [op1, op2], f"xchg {op1}, {op2}")
    return None


def translate_instruction_to_vm(insn: dict[str, Any], arch: str = "x64") -> VMInstruction | None:
    """Translate a native instruction to a VM instruction."""
    vm_insn = _translate_instruction_to_vm(insn, arch)
    if vm_insn is not None:
        for op in vm_insn.operands:
            if isinstance(op, int) and (op < -2147483648 or op > 2147483647):
                logger.debug(
                    "Operand %d exceeds VM 32-bit encoding for %r; skipping virtualization",
                    op,
                    insn.get("mnemonic", "?"),
                )
                return None
    return vm_insn


class VMProfile:
    """A VM profile defines the characteristics of a specific VM configuration."""

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
    VMProfile("simple", 0x00, "standard", {"rax": 0, "rcx": 1, "rdx": 2, "rbx": 3}),
    VMProfile("obfuscated", 0x80, "indirect", {"r8": 0, "r9": 1, "r10": 2, "r11": 3}, junk_handlers=5, obfuscate_handlers=True),
    VMProfile("stack_based", 0xC0, "stack", {"rsp": 0, "rbp": 1, "rsi": 2, "rdi": 3}, junk_handlers=10, obfuscate_handlers=True),
    VMProfile("register_based", 0x40, "register", {"r12": 0, "r13": 1, "r14": 2, "r15": 3}, junk_handlers=15, obfuscate_handlers=True),
]


def generate_multi_vm_dispatcher_x64(profile: VMProfile) -> str:
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
            junk_handlers_code += (
                f"""vm_{profile.name}_junk_{i}:
    nop
    nop
    jmp .vm_loop_{profile.name}

"""
            )

    return prelude + dispatch_loop + handlers_section + junk_handlers_code


def generate_multi_vm_handler_x64(opcode: int | VMOpcode, profile: VMProfile) -> str:
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
        mnemonic, _ = opcodes_with_regs[vm_opcode]
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
        return f"""{handler_name}:
    movzx ecx, byte [rsi]
    inc rsi
    movsx rax, dword [rsi]
    add rsi, 4
    {mnemonic} [rbx + rcx * 8], rax
    jmp vm_execute_{profile.name}
"""

    if opcode == VMOpcode.JMP:
        return f"""{handler_name}:
    movsx rax, dword [rsi]
    add rsi, rax
    jmp vm_execute_{profile.name}
"""

    return f"{handler_name}:\n    jmp vm_execute_{profile.name}\n"
