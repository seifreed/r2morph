#!/usr/bin/env python3
"""Run an independent second-pass review of published validation artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from r2morph.platform.elf_handler_parsing import parse_elf_header
from scripts.continuous_fuzz import run_campaign
from scripts.support_matrix import build_matrix
from scripts.virtualization_coverage import build_coverage_inventory

_EXPECTED_BENCHMARK_TOOLS = {
    "radare2",
    "objdump",
    "angr",
    "unicorn",
    "triton",
    "ida-pro",
    "ghidra",
    "custom",
}
_CURRENT_CORPUS_REPORT = "protection-adversarial-corpus-2026-09-05-fa85d18-triton.json"
_CURRENT_GHIDRA_REPORT = "protection-ghidra-corpus-2026-09-04-88258a05.json"
_CURRENT_IDA_REPORT = "protection-ida-mcp-corpus-2026-09-05-7c3d4f32.json"
_CURRENT_FUZZ_REPORT = "protection-fuzz-2026-09-05-2e4ad8e.json"


def _check(name: str, passed: bool, detail: str) -> dict[str, object]:
    return {"name": name, "status": "passed" if passed else "failed", "detail": detail}


def _review_virtualization(root: Path) -> dict[str, object]:
    inventory = build_coverage_inventory(root / "fixtures" / "dataset")
    passed = inventory["unclassified"] == [] and inventory["covered_capability_count"] == inventory["capability_count"]
    return _check(
        "virtualization_fixture_coverage", passed, f"{inventory['fixture_count']} fixtures, no unclassified entries"
    )


def _review_matrix(root: Path) -> dict[str, object]:
    path = root / "docs" / "support-matrix.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    matrix = build_matrix(document)
    passed = document.get("matrix") == matrix
    return _check("support_matrix_consistency", passed, f"{matrix['cell_count']} explicit cells")


def _review_benchmark(root: Path) -> dict[str, object]:
    path = root / "docs" / "protection-adversarial-benchmark.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    tools = {item.get("tool") for item in document.get("tools", []) if isinstance(item, dict)}
    completed = [item for item in document.get("tools", []) if item.get("status") == "completed"]
    unavailable = [item for item in document.get("tools", []) if item.get("status") == "unavailable"]
    valid_unavailable = all(isinstance(item.get("reason"), str) for item in unavailable)
    valid_completed = all(
        isinstance(item.get("original"), dict) and isinstance(item.get("protected"), dict) for item in completed
    )
    passed = tools == _EXPECTED_BENCHMARK_TOOLS and valid_unavailable and valid_completed
    return _check(
        "adversarial_benchmark_evidence", passed, f"{len(completed)} completed, {len(unavailable)} unavailable"
    )


def _review_corpus_benchmark(root: Path) -> dict[str, object]:
    path = root / "docs" / _CURRENT_CORPUS_REPORT
    document = json.loads(path.read_text(encoding="utf-8"))
    samples = document.get("samples", [])
    expected_count = document.get("sample_count")
    sample_valid = isinstance(samples, list) and expected_count == len(samples) and expected_count > 0
    rows_valid = True
    for sample in samples if isinstance(samples, list) else []:
        if not isinstance(sample, dict):
            rows_valid = False
            break
        tool_rows = sample.get("tools", [])
        pass_rows = sample.get("passes", [])
        tool_names = {row.get("tool") for row in tool_rows if isinstance(row, dict)}
        pass_names = {row.get("pass_name") for row in pass_rows if isinstance(row, dict)}
        if tool_names != _EXPECTED_BENCHMARK_TOOLS or "CodeVirtualization" not in pass_names:
            rows_valid = False
            break
        if any(
            not isinstance(row.get("status"), str) or row.get("status") not in {"completed", "unavailable", "error"}
            for row in tool_rows
            if isinstance(row, dict)
        ):
            rows_valid = False
            break
        if any(
            not isinstance(row.get("error_type"), str) or not row["error_type"]
            for row in tool_rows
            if isinstance(row, dict) and row.get("status") == "error"
        ):
            rows_valid = False
            break
    summary = document.get("summary", {})
    completed = sum(
        1
        for sample in samples
        if isinstance(samples, list) and isinstance(sample, dict)
        for row in sample.get("tools", [])
        if isinstance(row, dict) and row.get("status") == "completed"
    )
    unavailable = sum(
        1
        for sample in samples
        if isinstance(samples, list) and isinstance(sample, dict)
        for row in sample.get("tools", [])
        if isinstance(row, dict) and row.get("status") == "unavailable"
    )
    errors = sum(
        1
        for sample in samples
        if isinstance(samples, list) and isinstance(sample, dict)
        for row in sample.get("tools", [])
        if isinstance(row, dict) and row.get("status") == "error"
    )
    summary_valid = summary == {
        "completed_tool_runs": completed,
        "error_tool_runs": errors,
        "unavailable_tool_runs": unavailable,
    }
    passed = sample_valid and rows_valid and summary_valid
    return _check(
        "adversarial_corpus_evidence",
        passed,
        f"{expected_count} samples, {completed} completed tool runs, {errors} errors",
    )


def _review_ghidra_corpus(root: Path) -> dict[str, object]:
    path = root / "docs" / _CURRENT_GHIDRA_REPORT
    document = json.loads(path.read_text(encoding="utf-8"))
    samples = document.get("samples", [])
    expected_count = document.get("sample_count")
    rows_valid = isinstance(samples, list) and expected_count == len(samples) and expected_count > 0
    completed = 0
    for sample in samples if isinstance(samples, list) else []:
        tools = sample.get("tools", []) if isinstance(sample, dict) else []
        row = tools[0] if len(tools) == 1 and isinstance(tools[0], dict) else None
        if row is None or row.get("tool") != "ghidra" or row.get("status") != "completed":
            rows_valid = False
            continue
        original = row.get("original", {})
        protected = row.get("protected", {})
        if original.get("status") != "completed" or protected.get("status") != "completed":
            rows_valid = False
            continue
        completed += 2
    summary = document.get("summary", {})
    summary_valid = summary == {
        "completed_analysis_runs": completed,
        "error_analysis_runs": 0,
        "timeout_analysis_runs": 0,
    }
    passed = rows_valid and summary_valid
    return _check("ghidra_corpus_evidence", passed, f"{expected_count} samples, {completed} completed analyses")


def _review_ida_corpus(root: Path) -> dict[str, object]:
    """Validate the current full-corpus IDA MCP measurement."""
    path = root / "docs" / _CURRENT_IDA_REPORT
    document = json.loads(path.read_text(encoding="utf-8"))
    sample_count = document.get("sample_count")
    runs = document.get("analysis_runs", {})
    passed = (
        document.get("status") == "completed"
        and document.get("tool") == "ida-pro-mcp"
        and isinstance(sample_count, int)
        and runs == {"original": sample_count, "protected": sample_count, "total": sample_count * 2}
        and document.get("error_analysis_runs") == 0
    )
    return _check("ida_corpus_evidence", passed, f"{sample_count} samples, {runs.get('total', 0)} completed analyses")


def _review_fuzz_artifact(root: Path) -> dict[str, object]:
    """Validate the bounded campaign recorded for all four fuzz targets."""
    path = root / "docs" / _CURRENT_FUZZ_REPORT
    document = json.loads(path.read_text(encoding="utf-8"))
    cases = document.get("cases")
    target_runs = document.get("target_runs")
    expected_targets = {"binary_parsers", "vm_dispatcher", "relocations", "binary_rewriter"}
    passed = (
        isinstance(cases, int)
        and cases > 0
        and document.get("failure_count") == 0
        and isinstance(target_runs, dict)
        and set(target_runs) == expected_targets
        and all(target_runs[target] == cases for target in expected_targets)
    )
    total_runs = sum(target_runs.values()) if isinstance(target_runs, dict) else 0
    return _check("parser_rewriter_fuzz_campaign", passed, f"{total_runs} target runs, 0 failures")


def _review_fixtures(root: Path) -> dict[str, object]:
    dataset = root / "fixtures" / "dataset"
    candidates = sorted(dataset.glob("elf_vm_*_x86_64"))
    valid = 0
    for path in candidates:
        header, is_64bit, _little_endian = parse_elf_header(path)
        if header is not None and is_64bit is True:
            valid += 1
    return _check(
        "virtualization_fixture_headers",
        valid == len(candidates) and valid > 0,
        f"{valid}/{len(candidates)} valid ELF64 headers",
    )


def review(root: Path) -> dict[str, Any]:
    fuzz = run_campaign(cases=64, seed=20260827, max_payload=512)
    checks = [
        _review_virtualization(root),
        _review_matrix(root),
        _review_benchmark(root),
        _review_corpus_benchmark(root),
        _review_ghidra_corpus(root),
        _review_ida_corpus(root),
        _review_fixtures(root),
        _review_fuzz_artifact(root),
        _check("independent_fuzz_recheck", fuzz["failure_count"] == 0, f"{fuzz['cases']} cases, 0 failures expected"),
    ]
    return {
        "schema_version": 1,
        "review_type": "automated-independent-second-pass",
        "human_signoff": "not-attested",
        "checks": checks,
        "passed": all(check["status"] == "passed" for check in checks),
        "limitations": ["This artifact is not a substitute for an external human review."],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = review(args.root.resolve())
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
