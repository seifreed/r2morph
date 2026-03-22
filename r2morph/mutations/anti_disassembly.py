"""
Anti-Disassembly - Techniques to confuse disassemblers.

Implements various anti-disassembly techniques:
- False disassembly (overlapping instructions)
- SEH-based obfuscation
- Jump into middle of instruction
- Polyglot code (valid as multiple architectures)
- Opaque predicates that confuse analysis
- Trampoline-based obfuscation

Anti-disassembly makes static analysis difficult by:
- Creating false control flow paths
- Using overlapping instructions
- Exploiting differences between linear and recursive disassembly
- Injecting SEH handlers that confuse analysis tools
"""

import logging
import random
from dataclasses import dataclass
from enum import Enum
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


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
; Trampoline: indirect jump through calculated address
call get_pc
get_pc:
pop rax
add rax, 0x10
jmp rax              ; Jump forward
db 0x90, 0x90, 0x90  ; Never executed
db 0x90, 0x90, 0x90
real_code:
xor eax, eax
""",
        bytes_hex="E800000000588D400A4A90C4831C0FFC031C0",
        size=16,
        disasm_type=AntiDisasmType.TRAMPOLINE,
        description="Trampoline through calculated address",
    ),
]

ALL_ANTI_DISASM_X64 = (
    OVERLAPPING_X64 + JUMP_MIDDLE_X64 + FALSE_BRANCH_X64 + SEH_BASED_X64 + POLYGLOT_X64_86 + TRAMPOLINE_X64
)


def generate_false_disasm_sequence(arch: str = "x64") -> AntiDisasmSnippet:
    """
    Generate a random false disassembly sequence.

    Args:
        arch: Architecture (x64 or x86)

    Returns:
        AntiDisassemblySnippet
    """
    if arch == "x64":
        snippets = OVERLAPPING_X64 + JUMP_MIDDLE_X64 + FALSE_BRANCH_X64
    else:
        snippets = OVERLAPPING_X64 + JUMP_MIDDLE_X64 + FALSE_BRANCH_X64

    return random.choice(snippets)


def generate_opaque_predicate_x64(arch: str = "x64") -> str:
    """
    Generate opaque predicate that looks complex but has known result.

    Returns:
        Assembly string
    """
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
    """
    Generate a nop sled with obfuscated instructions.

    Args:
        size: Size of sled in bytes

    Returns:
        Assembly string
    """
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


class AntiDisassemblyPass(MutationPass):
    """
    Mutation pass that injects anti-disassembly techniques.

    Inserts code sequences that confuse disassemblers while
    maintaining correct execution semantics.

    Config options:
        - probability: Probability of injecting at each point (default: 0.3)
        - techniques: List of techniques to use (default: all)
        - seh_enabled: Enable SEH-based techniques (default: False, dangerous)
        - max_injections: Maximum injections per function (default: 5)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="AntiDisassembly", config=config)
        self.probability = self.config.get("probability", 0.3)
        self.techniques = self.config.get("techniques", list(AntiDisasmType))
        self.seh_enabled = self.config.get("seh_enabled", False)
        self.max_injections = self.config.get("max_injections", 5)
        self.set_support(
            formats=("ELF", "PE", "Mach-O"),
            architectures=("x86_64", "x86"),
            validators=("structural",),
            stability="experimental",
            notes=(
                "injects anti-disassembly techniques",
                "confuses linear and recursive disassemblers",
                "SEH techniques may cause issues on some platforms",
            ),
        )

    def _get_snippets_for_arch(self, arch: str) -> list[AntiDisasmSnippet]:
        """Get anti-disasm snippets for architecture."""
        if arch == "x64":
            snippets = ALL_ANTI_DISASM_X64.copy()
        else:
            snippets = OVERLAPPING_X64 + JUMP_MIDDLE_X64 + FALSE_BRANCH_X64.copy()

        if not self.seh_enabled:
            snippets = [s for s in snippets if s.disasm_type != AntiDisasmType.SEH_BASED]

        return snippets

    def _inject_snippet(self, binary: Binary, addr: int, snippet: AntiDisasmSnippet) -> bool:
        """Inject a snippet at the given address."""
        try:
            snippet_bytes = bytes.fromhex(snippet.bytes_hex)
            return binary.write_bytes(addr, snippet_bytes)
        except Exception as e:
            logger.debug(f"Failed to inject snippet: {e}")
            return False

    def _inject_overlapping(self, binary: Binary, addr: int) -> bool:
        """Inject overlapping instruction pattern."""
        snippet = random.choice(OVERLAPPING_X64)
        try:
            snippet_bytes = bytes.fromhex(snippet.bytes_hex)
            return binary.write_bytes(addr, snippet_bytes)
        except Exception as e:
            logger.debug(f"Failed to inject overlapping pattern: {e}")
            return False

    def _inject_false_branch(self, binary: Binary, addr: int) -> bool:
        """Inject false branch pattern."""
        snippet = random.choice(FALSE_BRANCH_X64)
        try:
            snippet_bytes = bytes.fromhex(snippet.bytes_hex)
            return binary.write_bytes(addr, snippet_bytes)
        except Exception as e:
            logger.debug(f"Failed to inject false branch pattern: {e}")
            return False

    def _inject_jump_middle(self, binary: Binary, addr: int) -> bool:
        """Inject jump into middle of instruction."""
        snippet = random.choice(JUMP_MIDDLE_X64)
        try:
            snippet_bytes = bytes.fromhex(snippet.bytes_hex)
            return binary.write_bytes(addr, snippet_bytes)
        except Exception as e:
            logger.debug(f"Failed to inject jump-middle pattern: {e}")
            return False

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply anti-disassembly techniques.

        Args:
            binary: Binary to transform

        Returns:
            Statistics dictionary
        """
        self._reset_random()
        logger.info("Applying anti-disassembly techniques")

        functions = binary.get_functions()
        injected_count = 0
        injections_by_type = {t: 0 for t in AntiDisasmType}

        arch_info = binary.get_arch_info()
        arch = "x64" if arch_info.get("arch") in ("x86_64", "x64", "amd64") else "x86"
        snippets = self._get_snippets_for_arch(arch)

        for func in functions:
            if injected_count >= self.max_injections * len(functions):
                break

            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            if random.random() > self.probability:
                continue

            try:
                blocks = binary.get_basic_blocks(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get blocks: {e}")
                continue

            for block in blocks:
                if random.random() > 0.3:
                    continue

                block_addr = block.get("addr", 0)
                snippet = random.choice(snippets)

                mutation_checkpoint = self._create_mutation_checkpoint("anti_disasm")
                baseline = {}
                if self._validation_manager is not None:
                    baseline = self._validation_manager.capture_structural_baseline(binary, func["addr"])

                original_bytes = binary.read_bytes(block_addr, len(snippet.bytes_hex) // 2)
                if original_bytes and self._inject_snippet(binary, block_addr, snippet):
                    mutated_bytes = binary.read_bytes(block_addr, len(snippet.bytes_hex) // 2)
                    self._record_mutation(
                        function_address=func["addr"],
                        start_address=block_addr,
                        end_address=block_addr + len(snippet.bytes_hex) // 2 - 1,
                        original_bytes=original_bytes,
                        mutated_bytes=mutated_bytes if mutated_bytes else bytes.fromhex(snippet.bytes_hex),
                        original_disasm="original_bytes",
                        mutated_disasm=snippet.description,
                        mutation_kind="anti_disassembly",
                        metadata={
                            "disasm_type": snippet.disasm_type.value,
                            "structural_baseline": baseline,
                        },
                    )

                    if self._validation_manager is not None:
                        outcome = self._validation_manager.validate_mutation(
                            binary, self._records[-1].to_dict() if self._records else {}
                        )
                        if not outcome.passed and mutation_checkpoint is not None:
                            if self._session is not None:
                                self._session.rollback_to(mutation_checkpoint)
                            binary.reload()
                            if self._records:
                                self._records.pop()
                            if self._rollback_policy == "fail-fast":
                                raise RuntimeError("Mutation-level validation failed")
                            continue

                    injections_by_type[snippet.disasm_type] += 1
                    injected_count += 1

                logger.debug(f"Injected {snippet.disasm_type.value} at 0x{block.get('addr', 0):x}")

        return {
            "total_injections": injected_count,
            "injections_by_type": {t.value: count for t, count in injections_by_type.items()},
            "seh_enabled": self.seh_enabled,
            "architecture": arch,
        }
