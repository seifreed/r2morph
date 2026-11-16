"""Verify the completed differential and platform campaign evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = _ROOT / "docs/protection-differential-run-2026-11-16-43859887107.json"
_PLATFORM_PATH = _ROOT / "docs/protection-platform-evidence-2026-11-16-43859887107.json"
_READINESS_PATH = _ROOT / "docs/one-zero-readiness.json"
_SOURCE_COMMIT = "3857682ca05ebad1ad1b2aa84b4689c0090ea8c5"
_MAIN_COMMIT = "5696062eaa7d6874280e80a0c9db517603e3f8be"
_WORKFLOW_RUN_ID = 43_859_887_107
_RUNS_PER_PASS = 1086
_PLATFORM_CASE_COUNT = 74
_WORKFLOW_JOB_COUNT = 85
_COMPLETE_EVIDENCE_PERCENT = 100.0
_PUBLIC_SAMPLE_COUNT = 360
_PUBLIC_DIFFERENTIAL_CHECK_COUNT = 2160
_VM_FIXTURE_COUNT = 1005
_SHARD_COUNT = 48
_COMPOSITION_CASE_COUNT = 2208
_CROSS_FORMAT_CASE_COUNT = 3552
_CROSS_FORMAT_SKIPPED_COUNT = 480
_FUZZ_CASE_COUNT = 3072
_FUZZ_TARGET_RUN_COUNT = 30720
_DECOMPILER_BLOCKER_COUNT = 22
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
_PLATFORMS = {"elf-arm-32", "elf-arm64", "elf-x86-32", "macos-arm64", "windows-pe"}


def _report() -> dict[str, object]:
    return json.loads(_REPORT_PATH.read_text(encoding="utf-8"))


def test_differential_campaign_binds_successful_workflow_and_artifact_hashes() -> None:
    report = _report()
    workflow = report["workflow"]
    source_trees = report["source_tree_ids_unchanged_at_main"]

    expect(
        report["source_commit"] == _SOURCE_COMMIT
        and report["applies_to_main_commit"] == _MAIN_COMMIT
        and workflow["run_id"] == _WORKFLOW_RUN_ID
        and workflow["conclusion"] == "success"
        and workflow["completed_jobs"] == _WORKFLOW_JOB_COUNT
        and workflow["failed_jobs"] == 0
        and source_trees["r2morph"] == "e469025729ee6a07511b0d5b38d1860e40452baa"
        and source_trees["tests/integration"] == "8d1182089a37100a73345ed6c0dc2c5b99a0db02"
        and source_trees[".github/workflows"] == "8cda2409c281d5c2d086d4bcc5482ddfe9c9483c"
        and all(re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) for item in workflow["artifact_members"])
    )


def test_differential_campaign_covers_core_and_extended_pass_rows_without_failures() -> None:
    report = _report()
    campaigns = (report["core_passes"], report["extended_passes"])

    expect(
        tuple(row["name"] for row in report["core_passes"]["passes"]) == _CORE_PASSES
        and tuple(row["name"] for row in report["extended_passes"]["passes"]) == _EXTENDED_PASSES
        and all(campaign["pass_count"] == len(campaign["passes"]) for campaign in campaigns)
        and all(
            row["complete_evidence_runs"] == _RUNS_PER_PASS
            and row["complete_evidence_coverage_percent"] == _COMPLETE_EVIDENCE_PERCENT
            and row["applied_runs"] + row["omitted_runs"] == _RUNS_PER_PASS
            and row["error_runs"] == row["semantic_failures"] == row["runtime_observable_failures"] == 0
            for campaign in campaigns
            for row in campaign["passes"]
        )
    )


def test_differential_campaign_records_platform_smoke_and_artifact_outcomes() -> None:
    report = _report()
    platform = report["platform_smoke"]
    platform_summary = json.loads(_PLATFORM_PATH.read_text(encoding="utf-8"))
    compatibility = report["public_compatibility"]
    vm = report["vm_semantic"]

    expect(
        platform_summary["summary"]["status"] == "complete"
        and set(platform_summary["platforms"]) == _PLATFORMS
        and platform["complete_platforms"] == platform["platform_count"] == len(_PLATFORMS)
        and platform["case_count"] == _PLATFORM_CASE_COUNT
        and platform["failure_count"] == platform["error_count"] == platform["skipped_count"] == 0
        and platform["summary_sha256"] == hashlib.sha256(_PLATFORM_PATH.read_bytes()).hexdigest()
        and compatibility["samples"] == _PUBLIC_SAMPLE_COUNT
        and compatibility["differential_passed"] == _PUBLIC_DIFFERENTIAL_CHECK_COUNT
        and compatibility["differential_failed"] == compatibility["errors"] == 0
        and vm["fixture_count"] == vm["passed_count"] == _VM_FIXTURE_COUNT
        and vm["failed_count"] == 0
    )


def test_differential_campaign_records_composition_fuzz_and_known_skips() -> None:
    report = _report()
    composition = report["composition"]
    cross_format = report["cross_format_smoke"]
    fuzz = report["differential_fuzz"]

    expect(
        composition["shards"] == _SHARD_COUNT
        and composition["cases"] == _COMPOSITION_CASE_COUNT
        and composition["failures"] == composition["errors"] == composition["skipped"] == 0
        and cross_format["shards"] == _SHARD_COUNT
        and cross_format["cases"] == _CROSS_FORMAT_CASE_COUNT
        and cross_format["failures"] == cross_format["errors"] == 0
        and cross_format["skipped"] == _CROSS_FORMAT_SKIPPED_COUNT
        and cross_format["skip_reasons"] == {"Mach-O arm64 execution requires macOS": _CROSS_FORMAT_SKIPPED_COUNT}
        and fuzz["shards"] == _SHARD_COUNT
        and fuzz["cases"] == _FUZZ_CASE_COUNT
        and fuzz["target_runs"] == _FUZZ_TARGET_RUN_COUNT
        and fuzz["failure_count"] == 0
    )


def test_differential_campaign_keeps_unresolved_release_gates_open() -> None:
    report = _report()
    readiness = json.loads(_READINESS_PATH.read_text(encoding="utf-8"))
    report_reference = _REPORT_PATH.relative_to(_ROOT).as_posix()
    platform_reference = _PLATFORM_PATH.relative_to(_ROOT).as_posix()

    expect(
        report["readiness"]["published_correctness_results"] == "complete"
        and report["readiness"]["cross_platform_parity"] == "open"
        and report["readiness"]["all_named_adversarial_analyzers"] == "open"
        and report["readiness"]["published_resistance_results"] == "open"
        and report["readiness"]["decompiler_blocker_count"] == _DECOMPILER_BLOCKER_COUNT
        and report_reference in readiness["criteria"]["cross_platform_parity"]["evidence"]
        and platform_reference in readiness["criteria"]["cross_platform_parity"]["evidence"]
        and report_reference in readiness["criteria"]["published_correctness_results"]["evidence"]
        and readiness["criteria"]["cross_platform_parity"]["status"] == "open"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
    )
