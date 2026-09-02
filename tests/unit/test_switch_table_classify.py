"""Characterization of SwitchTableAnalyzer._classify_indirect_jump.

The classifier is pure pattern matching over a disassembly string; it does not
touch the bound binary, so a None binary is sufficient (no mock -- CLAUDE.md
sec.4). This pins the classification contract so the jump-table operand
matching can be extracted into a helper without changing behavior.
"""

from r2morph.analysis.switch_table import SwitchTableAnalyzer
from tests.utils.assertions import expect

_EXPECTED_BASE_DISPLACEMENT_4202496 = 0x402000
_EXPECTED_BASE_TABLE_ADDRESS_4202496 = 0x402000
_EXPECTED_JT_DISPLACEMENT_4214784 = 0x405000
_EXPECTED_JT_SCALE_4 = 4
_EXPECTED_PLT_DISPLACEMENT_4096 = 0x1000
_EXPECTED_SCALED_SCALE_8 = 8


def _classify(disasm: str):
    return SwitchTableAnalyzer(None)._classify_indirect_jump(0x1000, disasm, 0x2000)


def test_classify_indirect_jump_contract() -> None:
    # indexed_scaled_offset: index register + scale + displacement (no base, so
    # table_address stays None).
    jt = _classify("jmp [rax*4 + 0x405000]")
    expect(jt is not None)
    expect(jt.jump_type == "jumptable")
    expect(jt.index_register == "rax")
    expect(jt.scale == _EXPECTED_JT_SCALE_4)
    expect(jt.displacement == _EXPECTED_JT_DISPLACEMENT_4214784)
    expect(not (jt.base_register is not None))
    expect(not (jt.table_address is not None))

    # indexed_offset: base + displacement -> table_address is set.
    base = _classify("jmp [rbx + 0x402000]")
    expect(base is not None)
    expect(base.jump_type == "jumptable")
    expect(base.base_register == "rbx")
    expect(base.displacement == _EXPECTED_BASE_DISPLACEMENT_4202496)
    expect(base.table_address == _EXPECTED_BASE_TABLE_ADDRESS_4202496)

    # indexed: a bare base register.
    indexed = _classify("jmp [rax]")
    expect(indexed is not None)
    expect(indexed.jump_type == "jumptable")
    expect(indexed.base_register == "rax")

    # indexed_scaled: index + scale, no displacement.
    scaled = _classify("jmp [rax*8]")
    expect(scaled is not None)
    expect(scaled.jump_type == "jumptable")
    expect(scaled.index_register == "rax")
    expect(scaled.scale == _EXPECTED_SCALED_SCALE_8)

    # A [rip + disp] form matches a jump-table pattern first but is then
    # reclassified as plt by the PLT pattern; the operands are retained.
    plt = _classify("jmp [rip + 0x1000]")
    expect(plt is not None)
    expect(plt.jump_type == "plt")
    expect(plt.base_register == "rip")
    expect(plt.displacement == _EXPECTED_PLT_DISPLACEMENT_4096)

    # The bare register / absolute jump-table patterns match but extract no
    # operands, so the type is "jumptable" with empty operands.
    reg = _classify("jmp rax")
    expect(reg is not None)
    expect(reg.jump_type == "jumptable")
    expect(not (reg.base_register is not None))
    expect(not (reg.index_register is not None))

    # A non-jump instruction is not classified.
    expect(not (_classify("add rax, rbx") is not None))


def test_classify_sized_indirect_jump_extracts_table_index() -> None:
    """Sized memory operands retain their jump-table index and displacement."""
    jump = _classify("jmp qword [rax*8 + 0x405000]")
    expect(jump is not None and jump.index_register == "rax")
