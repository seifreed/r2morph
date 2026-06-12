"""Characterization of SwitchTableAnalyzer._classify_indirect_jump.

The classifier is pure pattern matching over a disassembly string; it does not
touch the bound binary, so a None binary is sufficient (no mock -- CLAUDE.md
sec.4). This pins the classification contract so the jump-table operand
matching can be extracted into a helper without changing behavior.
"""

from r2morph.analysis.switch_table import SwitchTableAnalyzer


def _classify(disasm: str):
    return SwitchTableAnalyzer(None)._classify_indirect_jump(0x1000, disasm, 0x2000)


def test_classify_indirect_jump_contract() -> None:
    # indexed_scaled_offset: index register + scale + displacement (no base, so
    # table_address stays None).
    jt = _classify("jmp [rax*4 + 0x405000]")
    assert jt is not None
    assert jt.jump_type == "jumptable"
    assert jt.index_register == "rax"
    assert jt.scale == 4
    assert jt.displacement == 0x405000
    assert jt.base_register is None
    assert jt.table_address is None

    # indexed_offset: base + displacement -> table_address is set.
    base = _classify("jmp [rbx + 0x402000]")
    assert base is not None
    assert base.jump_type == "jumptable"
    assert base.base_register == "rbx"
    assert base.displacement == 0x402000
    assert base.table_address == 0x402000

    # indexed: a bare base register.
    indexed = _classify("jmp [rax]")
    assert indexed is not None
    assert indexed.jump_type == "jumptable"
    assert indexed.base_register == "rax"

    # indexed_scaled: index + scale, no displacement.
    scaled = _classify("jmp [rax*8]")
    assert scaled is not None
    assert scaled.jump_type == "jumptable"
    assert scaled.index_register == "rax"
    assert scaled.scale == 8

    # A [rip + disp] form matches a jump-table pattern first but is then
    # reclassified as plt by the PLT pattern; the operands are retained.
    plt = _classify("jmp [rip + 0x1000]")
    assert plt is not None
    assert plt.jump_type == "plt"
    assert plt.base_register == "rip"
    assert plt.displacement == 0x1000

    # The bare register / absolute jump-table patterns match but extract no
    # operands, so the type is "jumptable" with empty operands.
    reg = _classify("jmp rax")
    assert reg is not None
    assert reg.jump_type == "jumptable"
    assert reg.base_register is None
    assert reg.index_register is None

    # A non-jump instruction is not classified.
    assert _classify("add rax, rbx") is None
