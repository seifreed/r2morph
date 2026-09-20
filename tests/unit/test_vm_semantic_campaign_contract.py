from __future__ import annotations

from r2morph.mutations.base import MutationRecord
from scripts.vm_semantic_campaign import _transformation_evidence
from tests.utils.assertions import expect


def test_transformation_evidence_records_applied_instruction_metadata() -> None:
    record = MutationRecord(
        "CodeVirtualization",
        0x1000,
        0x1000,
        0x1010,
        "90",
        "e9",
        "; original",
        "; vm",
        "code_virtualization",
        {
            "instructions_count": 3,
            "bytecode_size": 128,
            "affected_instruction_mnemonics": ["punpckldq", "movd", "punpckldq"],
        },
    )

    expect(
        _transformation_evidence([record])
        == [
            {
                "function_address": 0x1000,
                "start_address": 0x1000,
                "end_address": 0x1010,
                "instructions_count": 3,
                "bytecode_size": 128,
                "affected_instruction_mnemonics": ["movd", "punpckldq"],
            }
        ]
    )
