from __future__ import annotations

from pathlib import Path

from r2morph.mutations.base import MutationRecord
from scripts.vm_semantic_campaign import _transformation_evidence, select_latest_campaign_shard_reports
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


def test_campaign_shard_selection_uses_latest_attempt_per_seed_and_shard() -> None:
    reports = [
        Path(
            f"vm-semantic-campaign-{seed}-{shard}-45428767299-1/"
            f"vm-semantic-campaign-{seed}-{shard}.json"
        )
        for seed in (20260916, 20260917, 20260918)
        for shard in range(8)
    ]
    reports.extend(
        [
            Path("vm-semantic-campaign-20260917-1-45428767299-2/vm-semantic-campaign-20260917-1.json"),
            Path("vm-semantic-campaign-merged-45428767299-1/vm-semantic-campaign-merged.json"),
        ]
    )

    selected = select_latest_campaign_shard_reports(reports)

    expect(len(selected) == 24)
    expect(
        Path("vm-semantic-campaign-20260917-1-45428767299-2/vm-semantic-campaign-20260917-1.json")
        in selected
    )
    expect(
        Path("vm-semantic-campaign-20260917-1-45428767299-1/vm-semantic-campaign-20260917-1.json")
        not in selected
    )
