"""Regression coverage for virtualizing the implicit ``cdqe`` extension."""

from __future__ import annotations

from typing import Any

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme, extract_region
from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen import build_region_blob
from tests.utils.assertions import expect


def test_classify_cdqe_as_movxreg_sign_extend_eax_to_rax() -> None:
    instruction: dict[str, Any] = {
        "addr": 0x1000,
        "size": 2,
        "type": "mov",
        "opcode": "cdqe",
    }

    expect(_classify(instruction) == ["movxreg", "s", 32, 64, 0, 0])


def test_classify_partial_register_move_and_lower_to_width_preserving_stack_ops() -> None:
    instruction = {"addr": 0x1000, "size": 2, "type": "mov", "opcode": "mov al, 0"}

    expect(_classify(instruction) == ["movsub", 0, 0, True, 8])
    region = extract_region(
        [instruction, {"addr": 0x1002, "size": 1, "type": "ret", "opcode": "ret"}], randomness.Random(1)
    )
    expect(region is not None and ("vpop8", 0) in region.instructions)


def test_classify_memory_immediate_arithmetic_and_rotate_with_existing_microops() -> None:
    arithmetic = {"addr": 0x1000, "size": 7, "type": "add", "opcode": "add dword [rbp - 0xbc], 1"}
    rotate = {"addr": 0x1007, "size": 6, "type": "rol", "opcode": "rol dword [rbp - 4], 5"}

    expect(_classify(arithmetic) == ["opmemimm", "add", 1, 5, -0xBC, 32])
    expect(_classify(rotate) == ["shiftmem", "rol", 5, 5, -4, 32])


def test_classify_memory_imul_and_lower_to_flag_preserving_microop() -> None:
    instruction = {"addr": 0x1000, "size": 7, "type": "mul", "opcode": "imul eax, dword [rbp - 8], 7"}

    expect(_classify(instruction) == ["imulmem", 0, 7, 5, -8, 32])
    region = extract_region(
        [instruction, {"addr": 0x1007, "size": 1, "type": "ret", "opcode": "ret"}], randomness.Random(1)
    )
    expect(region is not None and ("vimul", 32) in region.instructions)
    expect(
        region is not None and build_region_blob(region, 0x500000, build_region_scheme(region, randomness.Random(2)))
    )
