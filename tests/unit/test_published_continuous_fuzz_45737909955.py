"""Pin the current-source file-output fuzz evidence to its reports."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/continuous-fuzz-2026-11-26-45737909955-summary.json"
_SOURCE = "3b23bd501b41dbda8b4feda1480acd88ce1f8e57"
_RUN_ID = 45_737_909_955
_SCRIPT_HASH = "63b320087dc0acf6fd8bb87c3db8c7b6e4f9359391f45585879a9d6822d50f7c"
_CASES = 5_000
_SEED = 20_260_827
_MAX_PAYLOAD = 4_096
_OUTPUT_PATH_RUNS = 157
_RUNS_PER_PLATFORM = _CASES * 10 + _OUTPUT_PATH_RUNS
_TOTAL_RUNS = _RUNS_PER_PLATFORM * 3
_TARGETS = {
    "assembling",
    "binary_parsers",
    "binary_rewriter",
    "binary_rewriter_output",
    "elf_header_parser",
    "macho_load_commands",
    "pe_header_parser",
    "relocations",
    "vm_bytecode",
    "vm_dispatcher",
    "vm_instruction_decoder",
}
_REPORTS = {
    "ubuntu-latest": (
        15079119872,
        "b4e9211dc48e4a7825b5c35ef18ae455b93cfbfda16ad19251649316c0ef9761",
    ),
    "macos-15": (
        15079482549,
        "b4e9211dc48e4a7825b5c35ef18ae455b93cfbfda16ad19251649316c0ef9761",
    ),
    "windows-latest": (
        15079098539,
        "7192900a7b66a1b9bf26a2b3108c9e4e54e1bebf6a02e85334f6809707434fb3",
    ),
}


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY.read_text(encoding="utf-8"))


def test_manifest_binds_successful_run_and_fuzzer_source() -> None:
    summary = _summary()
    workflow = summary["workflow"]
    configuration = summary["configuration"]

    expect(workflow["source_commit"] == _SOURCE)
    expect(workflow["run_id"] == _RUN_ID and workflow["status"] == "success")
    expect(workflow["url"] == f"https://github.com/seifreed/r2morph/actions/runs/{_RUN_ID}")
    expect(
        hashlib.sha256((_ROOT / configuration["source_script"]).read_bytes()).hexdigest()
        == _SCRIPT_HASH
        == configuration["source_script_sha256"]
    )
    expect(set(configuration["targets"]) == _TARGETS)
    expect(configuration["cases_per_target_per_platform"] == _CASES)
    expect(configuration["seed"] == _SEED)
    expect(configuration["max_payload_bytes"] == _MAX_PAYLOAD)


def test_platform_artifacts_pin_50157_runs_without_failures() -> None:
    summary = _summary()
    execution = summary["execution"]
    platforms = execution["platforms"]

    expect(set(platforms) == set(_REPORTS))
    expect(execution["total_target_runs"] == _TOTAL_RUNS)
    expect(execution["total_failures"] == 0)
    for platform, (artifact_id, report_hash) in _REPORTS.items():
        entry = platforms[platform]
        raw = (_ROOT / entry["report"]).read_bytes()
        report = json.loads(raw)

        expect(entry["artifact_id"] == artifact_id)
        expect(hashlib.sha256(raw).hexdigest() == report_hash == entry["report_sha256"])
        expect(len(raw) == entry["report_size_bytes"])
        expect(entry["target_runs"] == _RUNS_PER_PLATFORM and entry["failure_count"] == 0)
        expect(report["failures"] == [] and report["failure_count"] == 0)
        expect(report["cases"] == _CASES and report["seed"] == _SEED)
        expect(report["max_payload"] == _MAX_PAYLOAD)
        expect(set(report["target_runs"]) == _TARGETS)
        expect(report["target_runs"]["binary_rewriter_output"] == _OUTPUT_PATH_RUNS)
        expect(sum(report["target_runs"].values()) == _RUNS_PER_PLATFORM)


def test_manifest_keeps_semantic_and_release_gates_open() -> None:
    limits = " ".join(_summary()["limits"])

    expect("one ELF fixture" in limits)
    expect("not execution equivalence" in limits)
    expect("do not establish complete product parity or exhaustive fuzz coverage" in limits)
    expect("does not close cross-platform analyzer parity, all-named analyzer, or published resistance gates" in limits)
