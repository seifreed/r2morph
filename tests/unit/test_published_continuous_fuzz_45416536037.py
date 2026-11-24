"""Pin current-source continuous-fuzz evidence to the original workflow artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/continuous-fuzz-2026-11-24-45416536037-summary.json"
_SOURCE = "a61f599e8ca3db7898a8971ec26668c069fd937c"
_RUN_ID = 45_416_536_037
_SCRIPT_HASH = "471b130d72db7c6d643c3c856931181ad61c240ef9c621e9e82b1c98a99198fa"
_CASES_PER_TARGET = 5_000
_SEED = 20_260_827
_MAX_PAYLOAD_BYTES = 4_096
_RUNS_PER_PLATFORM = 50_000
_TOTAL_RUNS = 150_000
_DIAGNOSTICS = {"macho_load_commands.warning": 103}
_TARGETS = {
    "assembling",
    "binary_parsers",
    "binary_rewriter",
    "elf_header_parser",
    "macho_load_commands",
    "pe_header_parser",
    "relocations",
    "vm_bytecode",
    "vm_dispatcher",
    "vm_instruction_decoder",
}
_PLATFORMS = {
    "macos-15": (
        14932602168,
        "sha256:84f5d8467a122756029560582e583bb846ef26df18570ba78248da60df43ff4b",
        "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
    ),
    "ubuntu-latest": (
        14933015357,
        "sha256:beea1810bb9bae7aae442157449195bac52c006336a3508410487802be798d8f",
        "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
    ),
    "windows-latest": (
        14933290192,
        "sha256:63911e047df5e3c4084a602fd8b0af554a4f4df8f41f51304a64ae4705f8d04a",
        "03cdcbe0b6a4fe2a373d605ba4bc1ed40d669674ba30614feb61988b7a1bd21c",
    ),
}


def test_manifest_binds_successful_current_source_run() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    workflow = summary["workflow"]
    configuration = summary["configuration"]

    expect(workflow["source_commit"] == _SOURCE and workflow["run_id"] == _RUN_ID and workflow["status"] == "success")
    expect(
        hashlib.sha256((_ROOT / configuration["source_script"]).read_bytes()).hexdigest()
        == _SCRIPT_HASH
        == configuration["source_script_sha256"]
    )
    expect(configuration["cases_per_target_per_platform"] == _CASES_PER_TARGET)
    expect(configuration["seed"] == _SEED)
    expect(configuration["max_payload_bytes"] == _MAX_PAYLOAD_BYTES)
    expect(set(configuration["targets"]) == _TARGETS)


def test_platform_reports_match_artifact_hashes_and_have_no_failures() -> None:
    summary = json.loads(_SUMMARY.read_text(encoding="utf-8"))
    execution = summary["execution"]
    platforms = execution["platforms"]

    expect(set(platforms) == set(_PLATFORMS))
    expect(execution["total_target_runs"] == _TOTAL_RUNS)
    expect(execution["total_failures"] == 0)
    for platform, (artifact_id, archive_hash, report_hash) in _PLATFORMS.items():
        entry = platforms[platform]
        raw = (_ROOT / entry["report"]).read_bytes()
        report = json.loads(raw)
        expect(entry["artifact_id"] == artifact_id)
        expect(entry["artifact_archive_sha256"] == archive_hash)
        expect(hashlib.sha256(raw).hexdigest() == report_hash == entry["report_sha256"])
        expect(entry["target_runs"] == _RUNS_PER_PLATFORM and entry["failure_count"] == 0)
        expect(entry["parser_diagnostic_counts"] == _DIAGNOSTICS)
        expect(report["failures"] == [] and report["failure_count"] == 0)
        expect(report["seed"] == _SEED and report["cases"] == _CASES_PER_TARGET)
        expect(report["max_payload"] == _MAX_PAYLOAD_BYTES)
        expect(set(report["target_runs"]) == _TARGETS)
        expect(set(report["target_runs"].values()) == {_CASES_PER_TARGET})


def test_bounded_fuzz_evidence_keeps_broader_gates_open() -> None:
    limits = json.loads(_SUMMARY.read_text(encoding="utf-8"))["limits"]

    expect(
        any("does not prove semantic equivalence for arbitrary transformed binaries" in limit for limit in limits)
        and any("do not establish complete product parity or exhaustive fuzz coverage" in limit for limit in limits)
        and any(
            "does not close the open differential, compatibility, or adversarial-resistance gates" in limit
            for limit in limits
        )
    )
