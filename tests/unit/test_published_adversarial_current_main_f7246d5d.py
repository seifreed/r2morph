"""Pin current-main local adversarial evidence and its bounded scope."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_PATH = "docs/protection-adversarial-current-main-local-2026-11-15-f7246d5d-summary.json"
_REPORT_PATH = "docs/protection-adversarial-current-main-local-2026-11-15-f7246d5d.json"
_SUMMARY = _ROOT / _SUMMARY_PATH
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_BLOCKERS = _ROOT / "docs/release-blockers.md"
_SOURCE_COMMIT = "f7246d5d7798a373cf1b7fb7801502a6606f88b1"
_EXPECTED_TOOL_SLOTS = 9
_COMPLETED_TOOL_SLOTS = 7
_UNAVAILABLE_TOOL_SLOTS = 2
_ZERO = 0


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _report() -> dict[str, object]:
    return _json(_ROOT / _REPORT_PATH)


def test_current_main_adversarial_report_is_bound_to_source_and_hash() -> None:
    summary = _json(_SUMMARY)
    report = summary["report"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and report["path"] == _REPORT_PATH
        and hashlib.sha256((_ROOT / _REPORT_PATH).read_bytes()).hexdigest() == report["sha256"]
    )


def test_current_main_ida_and_ghidra_complete_on_protected_fixture() -> None:
    summary = _json(_SUMMARY)
    measurement = summary["measurement"]
    analyzers = summary["analyzers"]
    tools = {tool["tool"]: tool for tool in _report()["tools"]}

    expect(
        analyzers["ida-pro"]["status"] == "completed"
        and analyzers["ghidra"]["status"] == "completed"
        and tools["ida-pro"]["status"] == "completed"
        and tools["ida-pro"]["protected"]["decompiler_status"] == "completed"
        and tools["ghidra"]["status"] == "completed"
        and tools["ghidra"]["protected"]["decompiler_status"] == "completed"
        and measurement["ida_function_delta"] > 0
        and measurement["ida_decompiler_bytes_delta"] > 0
        and measurement["ghidra_function_delta"] > 0
        and measurement["ghidra_decompiler_bytes_delta"] > 0
        and measurement["unicorn_exit_code_original"] == measurement["unicorn_exit_code_protected"]
    )


def test_current_main_adversarial_report_preserves_unavailable_slots() -> None:
    summary = _json(_SUMMARY)
    measurement = summary["measurement"]
    analyzers = summary["analyzers"]

    expect(
        measurement["expected_tool_slots"] == _EXPECTED_TOOL_SLOTS
        and measurement["completed_tool_slots"] == _COMPLETED_TOOL_SLOTS
        and measurement["unavailable_tool_slots"] == _UNAVAILABLE_TOOL_SLOTS
        and measurement["error_tool_slots"] == _ZERO
        and analyzers["binary-ninja"]["status"] == "unavailable"
        and analyzers["triton"]["status"] == "unavailable"
        and summary["observed_diagnostics"] == ["angr: Address 0x7002ce is not hooked"]
    )


def test_current_main_adversarial_evidence_keeps_release_gates_open() -> None:
    readiness = _json(_READINESS)
    blockers = " ".join(_BLOCKERS.read_text(encoding="utf-8").split())

    expect(
        readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and readiness["criteria"]["published_resistance_results"]["status"] == "open"
        and _REPORT_PATH in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
        and _SUMMARY_PATH in readiness["criteria"]["published_resistance_results"]["evidence"]
        and "Binary Ninja was unavailable" in blockers
        and "Triton was unavailable" in blockers
    )
