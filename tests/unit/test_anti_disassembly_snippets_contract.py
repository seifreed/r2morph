from __future__ import annotations

from r2morph.mutations.anti_disassembly_snippets import (
    ALL_ANTI_DISASM_X64,
    FALSE_BRANCH_X64,
    JUMP_MIDDLE_X64,
    OVERLAPPING_X64,
    SEH_BASED_X86,
    TRAMPOLINE_X64,
    AntiDisasmSnippet,
    AntiDisasmType,
    generate_false_disasm_sequence,
    generate_opaque_predicate_x64,
    generate_sled_obfuscation,
)


def test_anti_disassembly_snippets_cover_the_core_paths() -> None:
    snippet = AntiDisasmSnippet(
        asm="nop",
        bytes_hex="90",
        size=1,
        disasm_type=AntiDisasmType.OVERLAPPING,
        description="test",
    )
    assert snippet.size == 1
    assert snippet.disasm_type == AntiDisasmType.OVERLAPPING

    assert len(OVERLAPPING_X64) > 0
    assert len(JUMP_MIDDLE_X64) > 0
    assert len(FALSE_BRANCH_X64) > 0
    assert len(TRAMPOLINE_X64) > 0
    assert len(SEH_BASED_X86) > 0
    assert len(ALL_ANTI_DISASM_X64) > 0

    assert generate_false_disasm_sequence("x64").disasm_type in {
        AntiDisasmType.OVERLAPPING,
        AntiDisasmType.JUMP_INTO_MIDDLE,
        AntiDisasmType.FALSE_BRANCH,
    }
    assert isinstance(generate_opaque_predicate_x64(), str)
    assert len(generate_sled_obfuscation(size=16)) > 0
