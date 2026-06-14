from __future__ import annotations

from r2morph.analysis.dataflow_parsing import extract_registers_from_operand


def test_dataflow_parsing_extracts_register_shapes() -> None:
    registers = extract_registers_from_operand("qword ptr [rax + r8d*4], eax")

    assert ("rax", 64) in registers
    assert ("r8d", 32) in registers
    assert ("eax", 32) in registers
