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
    "binary-ninja",
    "custom",
}


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
        _review_fixtures(root),
        _check(
            "parser_rewriter_fuzz_campaign", fuzz["failure_count"] == 0, f"{fuzz['cases']} cases, 0 failures expected"
        ),
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
