"""Verify the published core and extended differential campaign summary."""

from __future__ import annotations

import json
import re
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-differential-run-2026-11-16-43835267898.json"
_READINESS = _ROOT / "docs" / "one-zero-readiness.json"
_CORE_PASSES = (
    "BlockReordering",
    "CodeVirtualization",
    "ConstantUnfolding",
    "ControlFlowFlattening",
    "DeadCodeInjection",
    "InstructionExpansion",
    "InstructionSubstitution",
    "NopInsertion",
    "PatternSubstitution",
    "RegisterSubstitution",
)
_EXTENDED_PASSES = (
    "APIHashing",
    "AntiDisassembly",
    "CodeMobility",
    "DataFlowMutation",
    "FunctionOutlining",
    "ImportObfuscation",
    "OpaquePredicates",
    "PolymorphicEngine",
    "SelfModifyingCode",
    "ShortJumpPatching",
    "StackStrings",
    "StringObfuscation",
)
_PASS_RUNS = 1086
_COMPLETE_EVIDENCE_PERCENT = 100.0
_WORKFLOW_RUN_ID = 43835267898


def _report() -> dict[str, object]:
    return json.loads(_REPORT.read_text(encoding="utf-8"))


def test_differential_campaign_report_binds_source_and_raw_artifact_hashes() -> None:
    report = _report()

    expect(
        report["source_commit"] == "7d3e5946a41fd5578e01ecef680bbf7e2ecf6043"
        and report["workflow"]["run_id"] == _WORKFLOW_RUN_ID
        and report["workflow"]["conclusion"] == "success"
        and tuple(item["name"] for item in report["artifact_members"])
        == ("differential-corpus-merged.json", "extended-maturity-merged.json")
        and tuple(item["sha256"] for item in report["artifact_members"])
        == (
            "a4a9571247736ddd274ab8866ff3bde57b273e6efa4b4eaf632c3bd4d0fb4890",
            "b99b350ba41c6a88334d78fa7e47f51f5ba244a71acaf357f25f2993cf5d496a",
        )
        and all(re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) for item in report["artifact_members"])
    )


def test_differential_campaign_covers_core_and_extended_passes_without_observed_failures() -> None:
    report = _report()
    campaigns = (report["core_passes"], report["extended_passes"])

    expect(
        tuple(row["name"] for row in report["core_passes"]["passes"]) == _CORE_PASSES
        and tuple(row["name"] for row in report["extended_passes"]["passes"]) == _EXTENDED_PASSES
        and all(campaign["pass_count"] == len(campaign["passes"]) for campaign in campaigns)
        and all(
            row["complete_evidence_runs"] == _PASS_RUNS
            and row["complete_evidence_coverage_percent"] == _COMPLETE_EVIDENCE_PERCENT
            and row["error_runs"] == row["semantic_failures"] == row["runtime_observable_failures"] == 0
            for campaign in campaigns
            for row in campaign["passes"]
        )
        and report["campaign_outcomes"]["extended_maturity_evidence_blockers"] == {}
    )


def test_differential_campaign_keeps_platform_parity_open_and_registers_evidence() -> None:
    report = _report()
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    report_path = _REPORT.relative_to(_ROOT).as_posix()

    expect(
        report["campaign_outcomes"]["continuous_platform_gap_blockers"]
        == {"architectures": ["AArch64", "ARM", "x86"], "formats": ["Mach-O", "PE"]}
        and readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and readiness["criteria"]["published_correctness_results"]["status"] == "complete"
        and report_path in readiness["criteria"]["published_correctness_results"]["evidence"]
    )
