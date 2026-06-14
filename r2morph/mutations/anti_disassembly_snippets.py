"""Anti-disassembly snippet catalog and generator helpers."""

from __future__ import annotations

import random
from dataclasses import dataclass
from enum import Enum


class AntiDisasmType(Enum):
    """Types of anti-disassembly techniques."""

    OVERLAPPING = "overlapping"
    SEH_BASED = "seh_based"
    JUMP_INTO_MIDDLE = "jump_into_middle"
    POLYGLOT = "polyglot"
    FALSE_BRANCH = "false_branch"
    TRAMPOLINE = "trampoline"
    OPAQUE_PREDICATE = "opaque_predicate"


@dataclass
class AntiDisasmSnippet:
    """An anti-disassembly snippet."""

    asm: str
    bytes_hex: str
    size: int
    disasm_type: AntiDisasmType
    description: str


OVERLAPPING_X64 = [
    AntiDisasmSnippet(
        asm="""
jmp forward_one
db 0xE8, 0x05  ; CALL opcode looks like function call to linear disassembler
forward_one:
xor eax, eax     ; Real code continues here
""",
        bytes_hex="EB02E80531C0",
        size=6,
        disasm_type=AntiDisasmType.OVERLAPPING,
        description="Overlapping: JMP over CALL byte, linear disasm sees CALL",
    ),
    AntiDisasmSnippet(
        asm="""
call $+5
db 0x90, 0x90, 0x90, 0x90  ; NOP sled looks like code but is jumped over
xor eax, eax
""",
        bytes_hex="E8059090909031C0",
        size=8,
        disasm_type=AntiDisasmType.OVERLAPPING,
        description="CALL pushes address, then data follows",
    ),
    AntiDisasmSnippet(
        asm="""
jmp real_code
db 0xB8, 0x01, 0x00, 0x00, 0x00  ; Looks like MOV EAX, 1
real_code:
""",
        bytes_hex="EB05B801000000",
        size=7,
        disasm_type=AntiDisasmType.OVERLAPPING,
        description="JMP over data that looks like MOV instruction",
    ),
]

JUMP_MIDDLE_X64 = [
    AntiDisasmSnippet(
        asm="""
jmp target
db 0x00, 0x00  ; Middle of next instruction
target:
xor eax, eax    ; Real code
""",
        bytes_hex="EB0031C0",
        size=4,
        disasm_type=AntiDisasmType.JUMP_INTO_MIDDLE,
        description="Jump to middle of perceived instruction",
    ),
    AntiDisasmSnippet(
        asm="""
xor eax, eax
jz real_target  ; Always taken (eax is 0)
db 0xFF, 0xFF    ; Data that looks like code
real_target:
""",
        bytes_hex="31C07402FFFF",
        size=6,
        disasm_type=AntiDisasmType.JUMP_INTO_MIDDLE,
        description="JZ over data that disasm thinks is code",
    ),
]

FALSE_BRANCH_X64 = [
    AntiDisasmSnippet(
        asm="""
xor eax, eax
jnz never_taken    ; Never taken (ZF=1 after XOR)
mov eax, 0xDEADBEEF  ; Fake path (never executed)
never_taken:
mov eax, 1        ; Real path
""",
        bytes_hex="31C07505B8EFBEADDEB801000000",
        size=12,
        disasm_type=AntiDisasmType.FALSE_BRANCH,
        description="JNZ after XOR is never taken",
    ),
    AntiDisasmSnippet(
        asm="""
pushfq
or dword [rsp], 0x44   ; Set ZF, unset others
popfq
jz always_taken        ; Always taken
call fake_func         ; Never executed
fake_func:
ret
always_taken:
""",
        bytes_hex="9C48814424040000009D740BE8000000C3",
        size=14,
        disasm_type=AntiDisasmType.FALSE_BRANCH,
        description="Manually set ZF, conditional is always true",
    ),
]

SEH_BASED_X64 = [
    AntiDisasmSnippet(
        asm="""
; SEH-based anti-disassembly (x64)
pushfq
push handler
mov rax, [gs:0x00]      ; Get TEB
push handler_addr
xor rax, rax
div rax                 ; Exception!
handler:
popfq
mov eax, 0
""",
        bytes_hex="9C6848656C6C6572658B44700068AAAAAAAA4831C048F768000000009DB8000000",
        size=25,
        disasm_type=AntiDisasmType.SEH_BASED,
        description="SEH handler div by zero exception, execution continues",
    ),
]

SEH_BASED_X86 = [
    AntiDisasmSnippet(
        asm="""
; SEH-based anti-disassembly (x86)
push handler
push dword [fs:0]
mov [fs:0], esp
xor eax, eax
div eax           ; Exception!
handler:
pop dword [fs:0]
add esp, 4
mov eax, 0
""",
        bytes_hex="68AAAAAAAAFF35AAAAAAAA6467280031C0F7F0646789250000000083C404B800000000",
        size=28,
        disasm_type=AntiDisasmType.SEH_BASED,
        description="SEH div by zero exception handler",
    ),
]

POLYGLOT_X64_86 = [
    AntiDisasmSnippet(
        asm="""
; Polyglot: Valid x86 and x64 (but different behavior)
; x86: ADD ESP, 8 then RET
; x64: XOR EAX, 0x89 then INC EAX
db 0x83, 0xC4, 0x08, 0xC3, 0x48, 0x31, 0xC0, 0x90, 0xFF, 0xC0
""",
        bytes_hex="83C408C34831C090FFC0",
        size=10,
        disasm_type=AntiDisasmType.POLYGLOT,
        description="Polyglot code valid on multiple architectures with different semantics",
    ),
]

TRAMPOLINE_X64 = [
    AntiDisasmSnippet(
        asm="""
; Trampoline: indirect jump through calculated address.
; Layout (offsets relative to start of snippet):
;   0x00 call get_pc          ; 5 bytes -- pushes return = block+5
;   0x05 get_pc: pop rax      ; 1 byte  -- rax = block+5
;   0x06 add rax, 0x0F        ; 4 bytes -- rax = block+0x14 (= block+20)
;   0x0A jmp rax              ; 2 bytes -- lands at block+0x14 = end of
;                             ;            snippet, so the snippet behaves
;                             ;            as a semantic NOP and execution
;                             ;            continues with whatever followed
;                             ;            the original block.
;   0x0C db 0x90, 0x90, 0x90  ; 3 bytes -- decoy NOPs (never executed)
;   0x0F db 0x90, 0x90, 0x90  ; 3 bytes -- decoy NOPs (never executed)
;   0x12 real_code:
;        xor eax, eax         ; 2 bytes -- decoy (never executed); a linear
;                             ;            disassembler reads it as the
;                             ;            real entry.
""",
        # Previously this string was 37 hex characters (odd), so
        # ``bytes.fromhex`` raised ValueError and _inject_snippet caught the
        # exception, silently returning False. The trampoline technique was
        # therefore completely inert (no bytes ever written). The corrected
        # encoding below is 40 chars / 20 bytes; it implements the layout
        # documented in ``asm`` above and is a semantic NOP (control flow
        # falls through to the byte immediately after the snippet).
        bytes_hex="E800000000584883C00FFFE090909090909031C0",
        size=20,
        disasm_type=AntiDisasmType.TRAMPOLINE,
        description="Trampoline through calculated address",
    ),
]

ALL_ANTI_DISASM_X64 = (
    OVERLAPPING_X64 + JUMP_MIDDLE_X64 + FALSE_BRANCH_X64 + SEH_BASED_X64 + POLYGLOT_X64_86 + TRAMPOLINE_X64
)


def generate_false_disasm_sequence(arch: str = "x64") -> AntiDisasmSnippet:
    """Generate a random false disassembly sequence."""
    if arch == "x64":
        snippets = OVERLAPPING_X64 + JUMP_MIDDLE_X64 + FALSE_BRANCH_X64
    else:
        snippets = OVERLAPPING_X64 + JUMP_MIDDLE_X64 + FALSE_BRANCH_X64
    return random.choice(snippets)


def generate_opaque_predicate_x64(arch: str = "x64") -> str:
    """Generate opaque predicate that looks complex but has known result."""
    predicates = [
        ("xor eax, eax\njz always_taken", "XOR sets ZF, JZ always taken"),
        ("mov eax, 1\ncmp eax, 0\njne always_taken", "1 != 0, JNE always taken"),
        ("mov eax, 0\ncmp eax, 0\nje always_taken", "0 == 0, JE always taken"),
        ("mov eax, -1\ncmp eax, 0\njl always_taken", "-1 < 0, JL always taken"),
        ("mov eax, 0xFFFFFFFF\ncmp eax, 0\njl always_taken", "-1 < 0, JL always taken"),
        ("mov eax, 0\ncmp eax, eax\nje always_taken", "R == R, JE always taken"),
        ("mov eax, 1\nmov ecx, 1\ncmp eax, ecx\nje always_taken", "1 == 1, JE always taken"),
    ]
    predicate, desc = random.choice(predicates)
    return predicate


def generate_sled_obfuscation(size: int = 16) -> str:
    """Generate a nop sled with obfuscated instructions."""
    nops = [
        "nop",
        "xchg ax, ax",
        "lea rax, [rax + 0]",
        "mov rax, rax",
        "push rax\npop rax",
        "jmp $+2\ndb 0xEB, 0x00  ; jmp over nop",
    ]

    total_nops = size // 2
    sled = []

    for _ in range(total_nops):
        sled.append(random.choice(nops))

    return "\n".join(sled)


__all__ = [
    "ALL_ANTI_DISASM_X64",
    "AntiDisasmSnippet",
    "AntiDisasmType",
    "FALSE_BRANCH_X64",
    "JUMP_MIDDLE_X64",
    "OVERLAPPING_X64",
    "POLYGLOT_X64_86",
    "SEH_BASED_X64",
    "SEH_BASED_X86",
    "TRAMPOLINE_X64",
    "generate_false_disasm_sequence",
    "generate_opaque_predicate_x64",
    "generate_sled_obfuscation",
]
