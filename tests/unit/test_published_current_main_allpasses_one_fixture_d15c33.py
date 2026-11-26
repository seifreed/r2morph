"""Pin current-main all-pass analyzer coverage for one repository fixture."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-adversarial-local-current-main-allpasses-one-fixture-2026-11-26-d15c33-summary.json"
_RAW = _ROOT / "docs/protection-adversarial-local-current-main-allpasses-one-fixture-2026-11-26-d15c33.json.gz"
_FIXTURE = _ROOT / "fixtures/dataset/elf_vm_arith_x86_64"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_main_allpasses_one_fixture_d15c33.py"
_SOURCE_COMMIT = "d15c33bdf4932c25ba89e212ab808e2ad7c42814"
_FIXTURE_SHA256 = "9311646e6eafa4829e06e619c251bd53e8ee676edee8e7fa2cfccd671a528d00"
_RAW_SHA256 = "d6deb190d8c20dac2b07f973e5089062061581a8bec3553aac92a565d962fa12"
_PASS_COUNT = 22
_TOOL_ROW_COUNT = 198
_COMPLETED_ROW_COUNT = 154
_UNAVAILABLE_ROW_COUNT = 44
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


def test_current_main_all_pass_analyzer_rows_are_hash_bound_and_bounded() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    raw_bytes = _RAW.read_bytes()
    raw = json.loads(gzip.decompress(raw_bytes))
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))
    analyzers = summary["scope"]["analyzers"]
    criterion = readiness["criteria"]["all_named_adversarial_analyzers"]

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and summary["scope"]["fixture_sha256"] == hashlib.sha256(_FIXTURE.read_bytes()).hexdigest() == _FIXTURE_SHA256
        and summary["raw_report"]["sha256"] == hashlib.sha256(raw_bytes).hexdigest() == _RAW_SHA256
        and summary["scope"]["pass_count"] == len(raw["pass_names"]) == _PASS_COUNT
        and summary["scope"]["tool_rows"] == len(raw["tools"]) == _TOOL_ROW_COUNT
        and summary["scope"]["completed_tool_rows"] == _COMPLETED_ROW_COUNT
        and summary["scope"]["unavailable_tool_rows"] == _UNAVAILABLE_ROW_COUNT
        and summary["scope"]["errored_tool_rows"] == 0
        and set(analyzers) == _EXPECTED_TOOLS
        and all(analyzer["runs"] == _PASS_COUNT for analyzer in analyzers.values())
        and all(analyzer["errors"] == 0 for analyzer in analyzers.values())
        and analyzers["ida-pro"]["completed"] == analyzers["ghidra"]["completed"] == _PASS_COUNT
        and analyzers["ida-pro"]["total_decompiler_error_count_delta"] == 0
        and analyzers["binary-ninja"]["unavailable"] == _PASS_COUNT
        and analyzers["triton"]["unavailable"] == _PASS_COUNT
        and summary["transformations"]["applied_passes"] == ["CodeVirtualization", "InstructionSubstitution"]
        and summary["transformations"]["code_virtualization"]
        == {
            "status": "applied",
            "functions_virtualized": 1,
            "unsupported_functions": 0,
            "partial_virtualization": 0,
        }
        and criterion["status"] == "open"
        and "binary-ninja" in criterion["optional_analyzers"]
        and _SUMMARY.relative_to(_ROOT).as_posix() in criterion["evidence"]
        and _TEST_PATH in criterion["evidence"]
        and summary["limits"]
    )
