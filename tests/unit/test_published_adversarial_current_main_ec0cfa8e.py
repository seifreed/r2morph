"""Pin current-main adversarial evidence with Triton available."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = "docs/protection-adversarial-current-main-local-2026-11-15-ec0cfa8e.json"
_SUMMARY_PATH = "docs/protection-adversarial-current-main-local-2026-11-15-ec0cfa8e-summary.json"
_SOURCE_COMMIT = "ec0cfa8e51d186eaa1e2fff64f7242b2fe2ee3d7"
_FIXTURE_PATH = "fixtures/dataset/elf_vm_arith_x86_64"
_EXPECTED_COMPLETED_TOOL_RUNS = 8
_EXPECTED_UNAVAILABLE_TOOL_RUNS = 1
_ZERO = 0


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_current_main_adversarial_report_matches_commit_and_hash() -> None:
    summary = _json(_ROOT / _SUMMARY_PATH)
    report_metadata = summary["source_report"]
    report = _ROOT / _REPORT_PATH
    fixture = _ROOT / _FIXTURE_PATH

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and report_metadata == _REPORT_PATH
        and hashlib.sha256(report.read_bytes()).hexdigest() == summary["source_report_sha256"]
        and hashlib.sha256(fixture.read_bytes()).hexdigest() == summary["fixture"]["sha256"]
    )


def test_current_main_triton_completes_semantic_measurement() -> None:
    report = _json(_ROOT / _REPORT_PATH)
    summary = _json(_ROOT / _SUMMARY_PATH)
    tools = {row["tool"]: row for row in report["tools"]}
    triton = tools["triton"]
    observations = summary["observations"]

    expect(
        triton["status"] == "completed"
        and triton["original"]["semantically_supported_instructions"]
        == observations["triton_original_semantically_supported"]
        and triton["protected"]["decoded_instructions"] == observations["triton_protected_decoded"]
        and triton["protected"]["semantically_supported_instructions"]
        == observations["triton_protected_semantically_supported"]
        and triton["protected"]["semantically_supported_instructions"] > _ZERO
    )


def test_current_main_adversarial_pair_preserves_native_result_and_decompiles() -> None:
    report = _json(_ROOT / _REPORT_PATH)
    tools = {row["tool"]: row for row in report["tools"]}

    expect(
        tools["unicorn"]["original"]["exit_code"] == tools["unicorn"]["protected"]["exit_code"]
        and tools["ida-pro"]["protected"]["decompiler_status"] == "completed"
        and tools["ghidra"]["protected"]["decompiler_status"] == "completed"
    )


def test_current_main_adversarial_evidence_keeps_open_gates_explicit() -> None:
    summary = _json(_ROOT / _SUMMARY_PATH)
    readiness = _json(_ROOT / "docs/one-zero-readiness.json")
    report = _json(_ROOT / _REPORT_PATH)
    tool_rows = {row["tool"]: row for row in report["tools"]}

    expect(
        summary["analyzer_summary"]["completed_tool_runs"] == _EXPECTED_COMPLETED_TOOL_RUNS
        and summary["analyzer_summary"]["unavailable_tool_runs"] == _EXPECTED_UNAVAILABLE_TOOL_RUNS
        and summary["analyzer_summary"]["error_tool_runs"] == _ZERO
        and tool_rows["binary-ninja"]["status"] == "unavailable"
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _REPORT_PATH in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
        and _SUMMARY_PATH in readiness["criteria"]["published_resistance_results"]["evidence"]
    )
