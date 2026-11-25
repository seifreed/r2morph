"""Pin the bounded current-source IDA analyzer sample."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, cast

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-adversarial-current-source-ida-one-fixture-2026-11-25-summary.json"
_REPORT = _ROOT / "docs/protection-adversarial-current-source-ida-one-fixture-2026-11-25.json"
_SOURCE_COMMIT = "6756d0b636ac3a64b4a96564c2671c1182f1acd2"
_REPORT_SHA256 = "78362f588416c33d84f83ceb17013240bad1b93415a2070958cb4fafb5f23bfd"
_FIXTURE_SHA256 = "9311646e6eafa4829e06e619c251bd53e8ee676edee8e7fa2cfccd671a528d00"
_EXPECTED_TOOLS = {
    "angr",
    "binary-ninja",
    "custom",
    "ghidra",
    "ida-pro",
    "objdump",
    "radare2",
    "triton",
    "unicorn",
}
_PATH_MARKERS = ("/Users/", "/Applications/", "/private/", f"{PurePosixPath('/', 'tmp')}/", "/home/")
_EXPECTED_IDA_METRICS = {
    "original_functions": 1,
    "protected_functions": 2,
    "original_decompiler_lines": 4,
    "protected_decompiler_lines": 30,
    "original_decompiler_bytes": 43,
    "protected_decompiler_bytes": 982,
    "decompiler_errors": 0,
}
_EXPECTED_LIMITATION_PREFIXES = (
    "One fixture and one pass",
    "Binary Ninja, Triton, and Ghidra",
    "This local sample does not close",
)


def _summary() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SUMMARY.read_text(encoding="utf-8")))


def _report() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_REPORT.read_text(encoding="utf-8")))


def test_local_ida_sample_binds_source_fixture_and_report_hashes() -> None:
    summary = _summary()
    fixture = _ROOT / "fixtures/dataset/elf_vm_arith_x86_64"

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["report"]["sha256"] == _REPORT_SHA256
        and hashlib.sha256(_REPORT.read_bytes()).hexdigest() == _REPORT_SHA256
        and summary["fixture"]["sha256"] == _FIXTURE_SHA256
        and hashlib.sha256(fixture.read_bytes()).hexdigest() == _FIXTURE_SHA256
    )


def test_local_ida_sample_completed_virtualization_and_preserves_analyzer_slots() -> None:
    report = _report()
    summary = _summary()
    tools = {row["tool"]: row for row in cast(list[dict[str, Any]], report["tools"])}

    expect(
        report["original"] == "elf_vm_arith_x86_64"
        and report["pass_names"] == ["CodeVirtualization"]
        and report["passes"][0]["status"] == "applied"
        and report["passes"][0]["functions_virtualized"] == 1
        and set(tools) == _EXPECTED_TOOLS
        and summary["scope"]["analyzer_slots"] == len(_EXPECTED_TOOLS)
        and set(summary["scope"]["completed_tools"])
        == {"angr", "custom", "ida-pro", "objdump", "radare2", "unicorn"}
        and tools["binary-ninja"]["status"] == "unavailable"
        and tools["triton"]["status"] == "unavailable"
        and tools["ghidra"]["status"] == "unavailable"
    )


def test_local_ida_sample_records_decompilation_without_errors() -> None:
    ida = next(row for row in _report()["tools"] if row["tool"] == "ida-pro")
    original = ida["original"]
    protected = ida["protected"]

    expect(
        ida["status"] == "completed"
        and original["decompiler_status"] == protected["decompiler_status"] == "completed"
        and original["functions"] == _EXPECTED_IDA_METRICS["original_functions"]
        and protected["functions"] == _EXPECTED_IDA_METRICS["protected_functions"]
        and original["decompiler_lines"] == _EXPECTED_IDA_METRICS["original_decompiler_lines"]
        and protected["decompiler_lines"] == _EXPECTED_IDA_METRICS["protected_decompiler_lines"]
        and original["decompiler_bytes"] == _EXPECTED_IDA_METRICS["original_decompiler_bytes"]
        and protected["decompiler_bytes"] == _EXPECTED_IDA_METRICS["protected_decompiler_bytes"]
        and original["decompiler_error_count"]
        + protected["decompiler_error_count"]
        == _EXPECTED_IDA_METRICS["decompiler_errors"]
    )


def test_local_ida_sample_keeps_open_release_gates_and_limits_explicit() -> None:
    summary = _summary()
    readiness = cast(
        dict[str, Any],
        json.loads((_ROOT / "docs/one-zero-readiness.json").read_text(encoding="utf-8")),
    )
    criteria = cast(dict[str, dict[str, Any]], readiness["criteria"])
    evidence = criteria["all_named_adversarial_analyzers"]["evidence"]
    paths = (f"docs/{_REPORT.name}", f"docs/{_SUMMARY.name}")
    limitations = cast(list[str], summary["limitations"])

    expect(
        all(path in evidence for path in paths)
        and criteria["all_named_adversarial_analyzers"]["status"] == "open"
        and criteria["published_resistance_results"]["status"] == "open"
        and len(limitations) == len(_EXPECTED_LIMITATION_PREFIXES)
        and all(
            limitation.startswith(prefix)
            for limitation, prefix in zip(limitations, _EXPECTED_LIMITATION_PREFIXES, strict=True)
        )
    )


def test_local_ida_sample_contains_no_host_paths() -> None:
    content = _REPORT.read_text(encoding="utf-8") + _SUMMARY.read_text(encoding="utf-8")

    expect(not any(marker in content for marker in _PATH_MARKERS))
