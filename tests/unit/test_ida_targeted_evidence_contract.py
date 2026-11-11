"""Regression checks for targeted IDA Pro campaign evidence."""

from __future__ import annotations

import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-ida-targeted-2026-11-11-c70a113b.json"
_EXPECTED_FIXTURES = {
    "elf_x86_64",
    "elf_vm_call_x86_64",
    "elf_vm_memwidth_x86_64",
    "elf_vm_fpenginearith_x86_64",
    "elf_vm_thread_xchg_x86_64",
}


def test_ida_targeted_campaign_decompiled_every_protected_fixture() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    results = report["results"]

    expect(
        {row["fixture"] for row in results} == _EXPECTED_FIXTURES
        and report["summary"]
        == {
            "analyzed_pairs": 5,
            "protected_decompilations_succeeded": 5,
            "virtualization_failures": 0,
            "partial_virtualizations": 0,
        }
        and all(
            row["ida"]["protected_decompilation_succeeded"]
            and row["virtualized_functions"] == 1
            and row["unsupported_functions"] == 0
            and row["partial_virtualization"] == 0
            for row in results
        )
    )


def test_ida_targeted_campaign_does_not_claim_general_resistance() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        "not evidence of general resistance" in report["interpretation"]
        and any("no CFG similarity" in item for item in report["limitations"])
        and any("no runtime-equivalence" in item for item in report["limitations"])
    )
