"""Pin the current-source IDA MCP spot check and its explicit limits."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/protection-adversarial-current-source-ida-one-fixture-2026-11-25-9c917.json"
_RAW = _ROOT / "docs/protection-adversarial-local-current-9c917.json.gz"
_FIXTURE = _ROOT / "fixtures/dataset/elf_vm_arith_x86_64"
_READINESS = _ROOT / "docs/one-zero-readiness.json"
_TEST_PATH = "tests/unit/test_published_current_source_ida_one_fixture_9c917.py"
_SOURCE_COMMIT = "9c9177952decf745674715563fbfa8e73a92a090"
_EXIT_CODE = 45
_ORIGINAL_SHA256 = "9311646e6eafa4829e06e619c251bd53e8ee676edee8e7fa2cfccd671a528d00"
_PROTECTED_SHA256 = "8b1f59b4361b491ebff8a4971df9b331c5560378f6c243669dfd3a173376c667"


def test_spot_check_binds_source_binaries_transformation_and_ida_results() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    raw_bytes = _RAW.read_bytes()
    raw = json.loads(gzip.decompress(raw_bytes))
    fixture_sha256 = hashlib.sha256(_FIXTURE.read_bytes()).hexdigest()
    readiness = json.loads(_READINESS.read_text(encoding="utf-8"))

    expect(
        summary["source_commit"] == _SOURCE_COMMIT
        and fixture_sha256 == summary["original_sha256"] == _ORIGINAL_SHA256
        and summary["protected_sha256"] == _PROTECTED_SHA256
        and summary["transformation"]
        == {
            "pass": "CodeVirtualization",
            "status": "applied",
            "functions_virtualized": 1,
            "unsupported_functions": 0,
            "partial_virtualization": 0,
        }
        and summary["behavioral_oracle"]
        == {
            "tool": "Unicorn",
            "original_exit_code": _EXIT_CODE,
            "protected_exit_code": _EXIT_CODE,
            "status": "completed",
        }
        and summary["ida_pro_mcp"]["analysis_status"] == "ok"
        and summary["ida_pro_mcp"]["auto_analysis_ready"]
        and summary["ida_pro_mcp"]["hexrays_ready"]
        and summary["ida_pro_mcp"]["original"]["decompile_status"] == "completed"
        and summary["ida_pro_mcp"]["protected"]["decompile_status"] == "completed"
        and summary["raw_report"]["sha256"] == hashlib.sha256(raw_bytes).hexdigest()
        and raw["passes"][0]["status"] == "applied"
        and raw["tools"]
        and any(
            row["tool"] == "unicorn" and row["original"]["exit_code"] == row["protected"]["exit_code"] == _EXIT_CODE
            for row in raw["tools"]
        )
        and summary["limits"]
        and readiness["criteria"]["all_named_adversarial_analyzers"]["status"] == "open"
        and _SUMMARY.relative_to(_ROOT).as_posix()
        in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
        and _TEST_PATH in readiness["criteria"]["all_named_adversarial_analyzers"]["evidence"]
    )
