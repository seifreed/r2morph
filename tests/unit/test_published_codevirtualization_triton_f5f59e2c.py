"""Pin current-main CodeVirtualization analyzer evidence with Triton available."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT_PATH = "docs/protection-adversarial-triton-codevirtualization-f5f59e2c.json"
_SUMMARY_PATH = "docs/protection-adversarial-triton-codevirtualization-f5f59e2c-summary.json"
_SOURCE_COMMIT = "f5f59e2c87574692bbc4013b03994c2a079aa938"
_FIXTURE_PATH = "fixtures/dataset/elf_vm_fppackedidxnb_x86_64"
_EXPECTED_FIXTURE_SHA256 = "a5b98d15463806174fdf87a6ac74ada040ac46690d2dfd0bbbbce4be6a7d63c7"
_EXPECTED_REPORT_SHA256 = "a72aa006bdd1a194565cda95c371b2fd6969c94918c2100a3142c5c622b4fd91"
_EXPECTED_SEMANTIC_INSTRUCTIONS = 8
_EXPECTED_ANALYZER_RUNS = 9
_EXPECTED_COMPLETED_ANALYZERS = 8
_EXPECTED_TOOL_NAMES = (
    "angr",
    "binary-ninja",
    "custom",
    "ghidra",
    "ida-pro",
    "objdump",
    "radare2",
    "triton",
    "unicorn",
)
_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", f"{PurePosixPath('/', 'tmp')}/", "/home/")


def _json(path: str) -> dict[str, object]:
    return json.loads((_ROOT / path).read_text(encoding="utf-8"))


def test_published_triton_report_matches_source_commit_and_fixture_hash() -> None:
    summary = _json(_SUMMARY_PATH)
    report = _ROOT / _REPORT_PATH
    fixture = _ROOT / _FIXTURE_PATH

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["source_report"] == _REPORT_PATH
        and summary["source_report_sha256"] == _EXPECTED_REPORT_SHA256
        and hashlib.sha256(report.read_bytes()).hexdigest() == _EXPECTED_REPORT_SHA256
        and summary["fixture"]["path"] == _FIXTURE_PATH
        and summary["fixture"]["sha256"] == _EXPECTED_FIXTURE_SHA256
        and hashlib.sha256(fixture.read_bytes()).hexdigest() == _EXPECTED_FIXTURE_SHA256
    )


def test_published_triton_report_records_fail_closed_virtualization_omission() -> None:
    report = _json(_REPORT_PATH)
    summary = _json(_SUMMARY_PATH)

    expect(
        report["pass_names"] == ["CodeVirtualization"]
        and report["passes"][0]["status"] == summary["observations"]["pass_status"] == "omitted"
        and report["passes"][0]["functions_virtualized"] == summary["observations"]["functions_virtualized"] == 0
        and report["passes"][0]["unsupported_functions"] == summary["observations"]["unsupported_functions"] == 1
    )


def test_published_triton_report_records_complete_instruction_semantics() -> None:
    report = _json(_REPORT_PATH)
    summary = _json(_SUMMARY_PATH)
    tools = {row["tool"]: row for row in report["tools"]}
    triton = tools["triton"]
    expected = summary["observations"]["triton"]

    expect(
        triton["status"] == expected["status"] == "completed"
        and triton["original"]["decoded_instructions"]
        == expected["original_decoded_instructions"]
        == _EXPECTED_SEMANTIC_INSTRUCTIONS
        and triton["original"]["semantically_supported_instructions"]
        == expected["original_semantically_supported_instructions"]
        == _EXPECTED_SEMANTIC_INSTRUCTIONS
        and triton["protected"]["decoded_instructions"]
        == expected["protected_decoded_instructions"]
        == _EXPECTED_SEMANTIC_INSTRUCTIONS
        and triton["protected"]["semantically_supported_instructions"]
        == expected["protected_semantically_supported_instructions"]
        == _EXPECTED_SEMANTIC_INSTRUCTIONS
        and triton["original"]["invalid_bytes"] == triton["protected"]["invalid_bytes"] == 0
        and triton["original"]["instruction_budget_exhausted"]
        is triton["protected"]["instruction_budget_exhausted"]
        is False
    )


def test_published_triton_report_accounts_for_each_analyzer_slot() -> None:
    report = _json(_REPORT_PATH)
    summary = _json(_SUMMARY_PATH)
    observations = summary["observations"]
    tools = {row["tool"]: row for row in report["tools"]}
    completed = sum(row["status"] == "completed" for row in report["tools"])
    unavailable = sum(row["status"] == "unavailable" for row in report["tools"])
    errors = sum(row["status"] == "error" for row in report["tools"])

    expect(
        tuple(sorted(tools)) == tuple(sorted(_EXPECTED_TOOL_NAMES))
        and len(tools) == observations["expected_analyzer_runs"] == _EXPECTED_ANALYZER_RUNS
        and completed == observations["completed_analyzer_runs"] == _EXPECTED_COMPLETED_ANALYZERS
        and unavailable == observations["unavailable_analyzer_runs"] == 1
        and errors == observations["error_analyzer_runs"] == 0
        and tools["binary-ninja"]["reason"] == "analyzer license is unavailable"
    )


def test_published_triton_report_keeps_readiness_gates_open() -> None:
    readiness = _json("docs/one-zero-readiness.json")
    all_analyzer_evidence = readiness["criteria"]["all_named_adversarial_analyzers"]
    resistance_evidence = readiness["criteria"]["published_resistance_results"]

    expect(
        readiness["status"] == "blocked"
        and all_analyzer_evidence["status"] == "open"
        and resistance_evidence["status"] == "open"
        and _REPORT_PATH in all_analyzer_evidence["evidence"]
        and _SUMMARY_PATH in all_analyzer_evidence["evidence"]
        and _SUMMARY_PATH not in resistance_evidence["evidence"]
    )


def test_published_triton_report_contains_no_analyst_host_paths() -> None:
    content = (_ROOT / _REPORT_PATH).read_text(encoding="utf-8") + (_ROOT / _SUMMARY_PATH).read_text(encoding="utf-8")

    expect(not any(marker in content for marker in _PATH_MARKERS))
