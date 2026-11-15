"""Verify hash-bound three-platform continuous fuzz evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_PLATFORMS = ("macos-15", "ubuntu-latest", "windows-latest")
_CASES_PER_TARGET = 5_000
_TARGET_COUNT = 10
_TARGET_RUNS_PER_PLATFORM = 50_000
_TARGET_RUNS_TOTAL = 150_000
_ZERO = 0
_EXPECTED_TARGETS = (
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
)
_CAMPAIGNS = (
    (
        "docs/continuous-fuzz-2026-11-15-f8586a1-summary.json",
        43_666_015_524,
        "f8586a1beb0068d53bcc9ebaf3009ce0e2e8e375",
        20260827,
        103,
        {
            "macos-15": "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
            "ubuntu-latest": "dc81e6ec70777b5547eb2ed9f07fcb33ec9566865f1d73ccfa8aa7618a79fa53",
            "windows-latest": "03cdcbe0b6a4fe2a373d605ba4bc1ed40d669674ba30614feb61988b7a1bd21c",
        },
    ),
    (
        "docs/continuous-fuzz-2026-11-15-09310435-summary.json",
        43_672_705_546,
        "0931043552012b20cc8338dd84fc2d42463a688b",
        20261115,
        108,
        {
            "macos-15": "b0f0b14824dd0bb84344637ed485108abd794b6a9c52afedcdab05b60a5aaa94",
            "ubuntu-latest": "b0f0b14824dd0bb84344637ed485108abd794b6a9c52afedcdab05b60a5aaa94",
            "windows-latest": "c2747f6e5d0a7b8c88e9cae749ffe77a3b12de04f0ac53a550e4806425e2954e",
        },
    ),
)


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("summary_path", "run_id", "source_revision", "seed", "artifact_hashes"),
    tuple((item[0], item[1], item[2], item[3], item[5]) for item in _CAMPAIGNS),
)
def test_published_fuzz_summary_binds_reports_to_successful_main_run(
    summary_path: str,
    run_id: int,
    source_revision: str,
    seed: int,
    artifact_hashes: dict[str, str],
) -> None:
    summary = _json(_ROOT / summary_path)
    reports = summary["reports"]
    expect(
        summary["workflow_run_id"] == run_id
        and summary["source_revision"] == source_revision
        and summary["workflow_conclusion"] == "success"
        and summary["seed"] == seed
        and set(reports) == set(_PLATFORMS)
        and all(
            hashlib.sha256((_ROOT / reports[platform]["path"]).read_bytes()).hexdigest() == reports[platform]["sha256"]
            and reports[platform]["source_artifact_sha256"] == artifact_hashes[platform]
            and reports[platform]["job_conclusion"] == "success"
            for platform in _PLATFORMS
        )
    )


@pytest.mark.parametrize("summary_path", tuple(item[0] for item in _CAMPAIGNS))
def test_published_fuzz_reports_cover_all_targets_without_failures(summary_path: str) -> None:
    summary = _json(_ROOT / summary_path)
    expect(
        summary["cases_per_target_per_platform"] == _CASES_PER_TARGET
        and summary["target_count"] == _TARGET_COUNT
        and summary["target_runs_per_platform"] == _TARGET_RUNS_PER_PLATFORM
        and summary["target_runs_total"] == _TARGET_RUNS_TOTAL
        and summary["failures_per_platform"] == _ZERO
        and all(
            (report := _json(_ROOT / summary["reports"][platform]["path"]))["cases"] == _CASES_PER_TARGET
            and report["seed"] == summary["seed"]
            and report["failure_count"] == _ZERO
            and report["failures"] == []
            and report["target_runs"] == dict.fromkeys(_EXPECTED_TARGETS, _CASES_PER_TARGET)
            for platform in _PLATFORMS
        )
    )


@pytest.mark.parametrize(("summary_path", "warning_count"), tuple((item[0], item[4]) for item in _CAMPAIGNS))
def test_published_fuzz_reports_preserve_parser_diagnostics(summary_path: str, warning_count: int) -> None:
    summary = _json(_ROOT / summary_path)
    expect(
        summary["parser_diagnostics_per_platform"] == {"macho_load_commands.warning": warning_count}
        and all(
            _json(_ROOT / summary["reports"][platform]["path"])["parser_diagnostic_counts"]
            == summary["parser_diagnostics_per_platform"]
            for platform in _PLATFORMS
        )
    )
