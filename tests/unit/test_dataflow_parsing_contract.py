from __future__ import annotations

from r2morph.analysis.dataflow_parsing import extract_registers_from_operand
from tests.utils.assertions import expect


def test_dataflow_parsing_extracts_register_shapes() -> None:
    registers = extract_registers_from_operand("qword ptr [rax + r8d*4], eax")

    expect(not (("rax", 64) not in registers))
    expect(not (("r8d", 32) not in registers))
    expect(not (("eax", 32) not in registers))


def test_dataflow_parsing_extracts_vector_register_sizes() -> None:
    registers = extract_registers_from_operand("vaddps ymm1, ymm2, ymm3")

    expect(
        {register for register in registers if register[0].startswith("ymm")}
        == {
            ("ymm1", 256),
            ("ymm2", 256),
            ("ymm3", 256),
        }
    )
