"""Regression coverage for code mobility and exception metadata."""

from __future__ import annotations

from r2morph.analysis.exception_models import ExceptionFrame
from r2morph.mutations.code_mobility import CodeMobilityPass
from tests._doubles.in_memory_mobility_binary import InMemoryMobilityBinary
from tests.utils.assertions import expect


def test_code_mobility_skips_function_with_lsda_metadata() -> None:
    binary = InMemoryMobilityBinary(
        regions={0x1000: b"\xcc" * 64, 0x2000: b"\x90" * 128},
        functions=[{"addr": 0x1000, "size": 64}],
        blocks=[{"addr": 0x1000, "size": 32, "type": "function"}],
        disasm=[{"disasm": "mov eax, ebx"}],
        sections=[{"name": ".text", "vaddr": 0x1000, "vsize": 64, "perm": "r-x"}],
    )
    exception_frames = {
        0x1000: ExceptionFrame(
            function_start=0x1000,
            function_end=0x1040,
            lsda_address=0x3000,
        )
    }

    plan = CodeMobilityPass({"probability": 1.0})._create_mobility_plan(
        binary,
        binary.get_functions(),
        exception_frames,
    )

    expect(plan.blocks == [])
