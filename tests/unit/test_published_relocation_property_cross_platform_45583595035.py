"""Pin the three-runner relocation property validation evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY = _ROOT / "docs/continuous-fuzz-relocation-property-2026-11-25-45583595035-summary.json"
_RUN_ID = 45_583_595_035
_SOURCE_COMMIT = "300194fa9a4ff5cade7e32535d9137ad7ab99ffe"
_PROPERTY_TEST = "tests/property/test_relocation_parser_properties.py"
_PROPERTY_TEST_HASH = "259b7909ef6070d3c1c57cee8def46c6355f06d3101a752be8bccb21ae13ff60"
_WORKFLOW = ".github/workflows/fuzz.yml"
_WORKFLOW_HASH = "15a8bebaae934f5679e67947ba759a1b46a5f2482cb556578f47e3aaa819c863"
_CASES_PER_TARGET = 5_000
_TEST_ITEMS_PER_PLATFORM = 2
_PLATFORM_COUNT = 3
_TOTAL_PROPERTY_TEST_ITEMS = 6
_RUNS_PER_PLATFORM = 50_000
_TOTAL_RUNS = 150_000
_ZERO = 0
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
    "ubuntu-latest": (
        139099459588,
        15007167690,
        "sha256:d60a6df8f2048ec67575ef7f60acb121d4dd8f2b7e487d2c709caf8b3de2042e",
        "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
    ),
    "macos-15": (
        139099459258,
        15008275928,
        "sha256:6aca97ac8be133d0b8f78bb59ea9ffaeac27315873c8b3f0e07a3abe9493ff53",
        "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
    ),
    "windows-latest": (
        139099459763,
        15008455537,
        "sha256:5f3dcce59015c4ac2dfe5fa5ead240b2577495da82e534423cbf0ca2f02900e3",
        "03cdcbe0b6a4fe2a373d605ba4bc1ed40d669674ba30614feb61988b7a1bd21c",
    ),
}


def _summary() -> dict[str, object]:
    return json.loads(_SUMMARY.read_text(encoding="utf-8"))


def test_manifest_binds_successful_cross_platform_property_run() -> None:
    summary = _summary()
    workflow = summary["workflow"]

    expect(
        workflow["run_id"] == _RUN_ID
        and workflow["status"] == "success"
        and workflow["source_commit"] == _SOURCE_COMMIT
        and workflow["url"] == f"https://github.com/seifreed/r2morph/actions/runs/{_RUN_ID}"
    )
    expect(
        summary["property_test"]["path"] == _PROPERTY_TEST
        and summary["property_test"]["pytest_items_passed_per_platform"] == _TEST_ITEMS_PER_PLATFORM
        and summary["property_test"]["sha256"] == _PROPERTY_TEST_HASH
        and hashlib.sha256((_ROOT / _PROPERTY_TEST).read_bytes()).hexdigest() == _PROPERTY_TEST_HASH
        and summary["property_test"]["workflow_path"] == _WORKFLOW
        and summary["property_test"]["workflow_sha256"] == _WORKFLOW_HASH
        and hashlib.sha256((_ROOT / _WORKFLOW).read_bytes()).hexdigest() == _WORKFLOW_HASH
    )


def test_runner_artifacts_and_fuzz_reports_are_accounted_for() -> None:
    summary = _summary()
    execution = summary["execution"]
    platforms = execution["platforms"]

    expect(
        set(platforms) == set(_PLATFORMS)
        and execution["platform_count"] == _PLATFORM_COUNT
        and execution["property_test_items_passed"] == _TOTAL_PROPERTY_TEST_ITEMS
        and execution["target_runs"] == _TOTAL_RUNS
        and execution["failure_count"] == _ZERO
    )
    for platform, (job_id, artifact_id, archive_hash, report_hash) in _PLATFORMS.items():
        entry = platforms[platform]
        report = json.loads((_ROOT / entry["report"]).read_bytes())
        raw = (_ROOT / entry["report"]).read_bytes()

        expect(entry["job_id"] == job_id and entry["artifact_id"] == artifact_id)
        expect(entry["artifact_archive_sha256"] == archive_hash)
        expect(entry["property_test_status"] == entry["fuzz_validator_status"] == "success")
        expect(entry["property_test_items_passed"] == _TEST_ITEMS_PER_PLATFORM)
        expect(hashlib.sha256(raw).hexdigest() == report_hash == entry["report_sha256"])
        expect(entry["target_runs"] == _RUNS_PER_PLATFORM and entry["failure_count"] == _ZERO)
        expect(report["failure_count"] == _ZERO and report["failures"] == [])
        expect(report["cases"] == _CASES_PER_TARGET and set(report["target_runs"]) == _TARGETS)
        expect(set(report["target_runs"].values()) == {_CASES_PER_TARGET})


def test_manifest_keeps_cross_platform_claim_bounded() -> None:
    limits = " ".join(_summary()["limits"])

    expect(
        "does not establish complete pass-by-platform parity" in limits
        and "do not prove semantic equivalence for arbitrary transformed binaries" in limits
        and "release gates remain open" in limits
    )
