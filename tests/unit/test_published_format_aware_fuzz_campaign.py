"""Regression checks for the pinned format-aware fuzz campaign."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-fuzz-format-aware-2026-11-11-95cff0fb.json"
_CURRENT_REPORT = _ROOT / "docs" / "protection-fuzz-format-aware-2026-11-12-04e2f5b4.json"
_CURRENT_RAW_REPORT = _ROOT / "docs" / "protection-fuzz-2026-11-12-04e2f5b4-output.json"
_WHEEL_REPORT = _ROOT / "docs" / "protection-fuzz-wheel-2026-11-12-8d6ceb6a.json"
_WHEEL_RAW_REPORT = _ROOT / "docs" / "protection-fuzz-wheel-2026-11-12-8d6ceb6a-output.json"
_PLATFORM_REPORT = _ROOT / "docs" / "protection-fuzz-wheel-platform-2026-11-12-df55c7a6.json"
_CURRENT_PLATFORM_REPORT = _ROOT / "docs" / "protection-fuzz-wheel-platform-2026-11-13-134af4ff.json"
_VM_DECODER_REPORT = _ROOT / "docs" / "protection-fuzz-vm-decoder-2026-11-14-03984513.json"
_VM_DECODER_RAW_REPORT = _ROOT / "docs" / "protection-fuzz-vm-decoder-2026-11-14-03984513-output.json"
_VM_DECODER_PLATFORM_REPORT = _ROOT / "docs" / "protection-fuzz-vm-decoder-platform-2026-11-14-03984513.json"
_CURRENT_PLATFORM_RUN = 43_331_412_474
_VM_DECODER_PLATFORM_RUN = 43_527_087_277
_PLATFORM_RUNNERS = {"ubuntu-latest", "macos-15", "windows-latest"}
_PLATFORM_WORKFLOW_RUN = 43_160_969_902
_WORKFLOW_RUN = 43_067_351_979
_WHEEL_WORKFLOW_RUN = 43_132_685_797
_CASES_PER_TARGET = 20_000
_TOTAL_TARGET_RUNS = 180_000
_TOTAL_PLATFORM_TARGET_RUNS = _TOTAL_TARGET_RUNS * len(_PLATFORM_RUNNERS)
_HOST_PATH_PREFIXES = ("/Users/", "/Applications/", "/private/", "/home/")
_EXPECTED_TARGETS = {
    "assembling",
    "binary_parsers",
    "elf_header_parser",
    "pe_header_parser",
    "macho_load_commands",
    "vm_dispatcher",
    "vm_bytecode",
    "relocations",
    "binary_rewriter",
}
_VM_DECODER_TARGETS = _EXPECTED_TARGETS | {"vm_instruction_decoder"}
_VM_DECODER_CASES = 5_000
_VM_DECODER_COMMIT = "03984513ad24062d6767682afff957828489f023"


def test_published_fuzz_campaign_covers_each_format_target() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    cases = report["cases"]

    expect(
        report["commit"] == "95cff0fb21a80fe43cda1a817cee718a45011b15"
        and report["workflow_run"] == _WORKFLOW_RUN
        and set(report["target_runs"]) == _EXPECTED_TARGETS
        and all(report["target_runs"][target] == cases == _CASES_PER_TARGET for target in _EXPECTED_TARGETS)
        and sum(report["target_runs"].values()) == _TOTAL_TARGET_RUNS
    )


def test_published_fuzz_campaign_reports_clean_parser_outcomes() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["status"] == "passed"
        and report["failure_count"] == 0
        and report["parser_diagnostic_counts"] == {"macho_load_commands.warning": 413}
    )


def test_published_fuzz_campaign_does_not_expose_host_paths() -> None:
    report = _REPORT.read_text(encoding="utf-8")

    expect(not any(prefix in report for prefix in _HOST_PATH_PREFIXES))


def test_current_local_fuzz_campaign_binds_summary_to_raw_report() -> None:
    report = json.loads(_CURRENT_REPORT.read_text(encoding="utf-8"))
    raw_hash = hashlib.sha256(_CURRENT_RAW_REPORT.read_bytes()).hexdigest()

    expect(
        report["commit"] == "04e2f5b4a365154712149ddc0f668d4b7692d495"
        and report["provenance"] == "local-source-tree"
        and report["campaign_report_sha256"] == raw_hash
    )


def test_current_local_fuzz_campaign_passes_each_declared_target() -> None:
    report = json.loads(_CURRENT_REPORT.read_text(encoding="utf-8"))

    expect(
        report["status"] == "passed"
        and report["failure_count"] == 0
        and set(report["target_runs"]) == _EXPECTED_TARGETS
        and all(report["target_runs"][target] == _CASES_PER_TARGET for target in _EXPECTED_TARGETS)
        and sum(report["target_runs"].values()) == _TOTAL_TARGET_RUNS
        and report["parser_diagnostic_counts"] == {"macho_load_commands.warning": 428}
    )


def test_current_local_fuzz_campaign_does_not_expose_host_paths() -> None:
    report = _CURRENT_REPORT.read_text(encoding="utf-8") + _CURRENT_RAW_REPORT.read_text(encoding="utf-8")

    expect(not any(prefix in report for prefix in _HOST_PATH_PREFIXES))


def test_current_wheel_fuzz_campaign_binds_summary_to_workflow_artifact() -> None:
    report = json.loads(_WHEEL_REPORT.read_text(encoding="utf-8"))
    raw_hash = hashlib.sha256(_WHEEL_RAW_REPORT.read_bytes()).hexdigest()

    expect(
        report["commit"] == "8d6ceb6a7f90cb39bc47c4bd9c4b36b14d758e31"
        and report["workflow_run"] == _WHEEL_WORKFLOW_RUN
        and report["provenance"] == "github-actions-installed-wheel"
        and report["campaign_report_sha256"] == raw_hash
    )


def test_current_wheel_fuzz_campaign_passes_each_declared_target() -> None:
    report = json.loads(_WHEEL_REPORT.read_text(encoding="utf-8"))

    expect(
        report["status"] == "passed"
        and report["failure_count"] == 0
        and set(report["target_runs"]) == _EXPECTED_TARGETS
        and all(report["target_runs"][target] == _CASES_PER_TARGET for target in _EXPECTED_TARGETS)
        and sum(report["target_runs"].values()) == _TOTAL_TARGET_RUNS
        and report["parser_diagnostic_counts"] == {"macho_load_commands.warning": 428}
        and report["runtime"]
        == {
            "os": "ubuntu-latest",
            "python": "3.12",
            "package_source": "installed-wheel",
        }
    )


def test_current_wheel_fuzz_campaign_does_not_expose_host_paths() -> None:
    report = _WHEEL_REPORT.read_text(encoding="utf-8") + _WHEEL_RAW_REPORT.read_text(encoding="utf-8")

    expect(not any(prefix in report for prefix in _HOST_PATH_PREFIXES))


def test_current_platform_fuzz_campaign_binds_to_the_workflow_run() -> None:
    report = json.loads(_PLATFORM_REPORT.read_text(encoding="utf-8"))

    expect(
        report["commit"] == "df55c7a6cea1e96ca687e96beb3ef0f77a450c65"
        and report["workflow_run"] == _PLATFORM_WORKFLOW_RUN
        and report["provenance"] == "github-actions-installed-wheel"
        and report["failure_count"] == 0
        and report["platform_count"] == len(_PLATFORM_RUNNERS)
        and report["total_target_runs"] == _TOTAL_PLATFORM_TARGET_RUNS
    )


def test_current_platform_fuzz_campaign_covers_all_targets_on_every_runner() -> None:
    report = json.loads(_PLATFORM_REPORT.read_text(encoding="utf-8"))
    platforms = report["platforms"]

    expect(
        {platform["runner"] for platform in platforms} == _PLATFORM_RUNNERS
        and all(
            platform["cases_per_target"] == _CASES_PER_TARGET
            and set(platform["target_runs"]) == _EXPECTED_TARGETS
            and all(platform["target_runs"][target] == _CASES_PER_TARGET for target in _EXPECTED_TARGETS)
            and platform["total_target_runs"] == _TOTAL_TARGET_RUNS
            and platform["failure_count"] == 0
            for platform in platforms
        )
    )


def test_current_platform_fuzz_campaign_binds_each_output_hash() -> None:
    report = json.loads(_PLATFORM_REPORT.read_text(encoding="utf-8"))

    expect(
        all(
            hashlib.sha256((_ROOT / "docs" / platform["campaign_report"]).read_bytes()).hexdigest()
            == platform["campaign_report_sha256"]
            for platform in report["platforms"]
        )
    )


def test_current_platform_fuzz_campaign_does_not_expose_host_paths() -> None:
    reports = [_PLATFORM_REPORT.read_text(encoding="utf-8")]
    report = json.loads(reports[0])
    reports.extend(
        (_ROOT / "docs" / platform["campaign_report"]).read_text(encoding="utf-8") for platform in report["platforms"]
    )

    expect(not any(prefix in "".join(reports) for prefix in _HOST_PATH_PREFIXES))


def test_latest_platform_fuzz_campaign_binds_to_the_current_commit_and_run() -> None:
    report = json.loads(_CURRENT_PLATFORM_REPORT.read_text(encoding="utf-8"))

    expect(
        report["commit"] == "134af4ff210b594d46e9803299c2111cfbebfa90"
        and report["workflow_run"] == _CURRENT_PLATFORM_RUN
        and report["provenance"] == "github-actions-installed-wheel"
        and report["failure_count"] == 0
        and report["total_target_runs"] == _TOTAL_PLATFORM_TARGET_RUNS
    )


def test_latest_platform_fuzz_campaign_covers_all_targets_on_all_runners() -> None:
    report = json.loads(_CURRENT_PLATFORM_REPORT.read_text(encoding="utf-8"))

    expect(
        {platform["runner"] for platform in report["platforms"]} == _PLATFORM_RUNNERS
        and all(
            platform["cases_per_target"] == _CASES_PER_TARGET
            and set(platform["target_runs"]) == _EXPECTED_TARGETS
            and all(platform["target_runs"][target] == _CASES_PER_TARGET for target in _EXPECTED_TARGETS)
            and platform["failure_count"] == 0
            for platform in report["platforms"]
        )
    )


def test_latest_platform_fuzz_campaign_binds_each_downloaded_report_hash() -> None:
    report = json.loads(_CURRENT_PLATFORM_REPORT.read_text(encoding="utf-8"))

    expect(
        all(
            hashlib.sha256((_ROOT / "docs" / platform["campaign_report"]).read_bytes()).hexdigest()
            == platform["campaign_report_sha256"]
            for platform in report["platforms"]
        )
    )


def test_latest_platform_fuzz_campaign_counts_recoverable_parser_warnings() -> None:
    report = json.loads(_CURRENT_PLATFORM_REPORT.read_text(encoding="utf-8"))

    expect(
        all(
            platform["parser_diagnostic_counts"] == {"macho_load_commands.warning": 418}
            for platform in report["platforms"]
        )
    )


def test_latest_platform_fuzz_campaign_does_not_expose_host_paths() -> None:
    report = json.loads(_CURRENT_PLATFORM_REPORT.read_text(encoding="utf-8"))
    reports = [_CURRENT_PLATFORM_REPORT.read_text(encoding="utf-8")]
    reports.extend(
        (_ROOT / "docs" / platform["campaign_report"]).read_text(encoding="utf-8") for platform in report["platforms"]
    )

    expect(not any(prefix in "".join(reports) for prefix in _HOST_PATH_PREFIXES))


def test_vm_decoder_campaign_binds_summary_to_raw_report() -> None:
    report = json.loads(_VM_DECODER_REPORT.read_text(encoding="utf-8"))
    raw_hash = hashlib.sha256(_VM_DECODER_RAW_REPORT.read_bytes()).hexdigest()

    expect(
        report["commit"] == _VM_DECODER_COMMIT
        and report["provenance"] == "local-source-tree"
        and report["campaign_report_sha256"] == raw_hash
    )


def test_vm_decoder_campaign_covers_every_target_without_failures() -> None:
    report = json.loads(_VM_DECODER_REPORT.read_text(encoding="utf-8"))

    expect(
        report["status"] == "passed"
        and report["failure_count"] == 0
        and report["cases"] == _VM_DECODER_CASES
        and set(report["target_runs"]) == _VM_DECODER_TARGETS
        and all(report["target_runs"][target] == _VM_DECODER_CASES for target in _VM_DECODER_TARGETS)
        and report["total_target_runs"] == _VM_DECODER_CASES * len(_VM_DECODER_TARGETS)
    )


def test_vm_decoder_campaign_does_not_expose_host_paths() -> None:
    report = _VM_DECODER_REPORT.read_text(encoding="utf-8") + _VM_DECODER_RAW_REPORT.read_text(encoding="utf-8")

    expect(not any(prefix in report for prefix in _HOST_PATH_PREFIXES))


def test_vm_decoder_platform_campaign_binds_to_successful_wheel_workflow() -> None:
    report = json.loads(_VM_DECODER_PLATFORM_REPORT.read_text(encoding="utf-8"))

    expect(
        report["commit"] == _VM_DECODER_COMMIT
        and report["workflow_run"] == _VM_DECODER_PLATFORM_RUN
        and report["provenance"] == "github-actions-installed-wheel"
        and report["failure_count"] == 0
        and report["status"] == "passed"
    )


def test_vm_decoder_platform_campaign_covers_all_targets_on_every_runner() -> None:
    report = json.loads(_VM_DECODER_PLATFORM_REPORT.read_text(encoding="utf-8"))

    expect(
        report["cases_per_target"] == _VM_DECODER_CASES
        and report["target_count"] == len(_VM_DECODER_TARGETS)
        and report["platform_count"] == len(_PLATFORM_RUNNERS)
        and report["total_target_runs"] == _VM_DECODER_CASES * len(_VM_DECODER_TARGETS) * len(_PLATFORM_RUNNERS)
        and {platform["runner"] for platform in report["platforms"]} == _PLATFORM_RUNNERS
        and all(
            platform["cases_per_target"] == _VM_DECODER_CASES
            and platform["failure_count"] == 0
            and set(platform["target_runs"]) == _VM_DECODER_TARGETS
            and all(platform["target_runs"][target] == _VM_DECODER_CASES for target in _VM_DECODER_TARGETS)
            for platform in report["platforms"]
        )
    )


def test_vm_decoder_platform_campaign_binds_each_downloaded_report_hash() -> None:
    report = json.loads(_VM_DECODER_PLATFORM_REPORT.read_text(encoding="utf-8"))

    expect(
        all(
            hashlib.sha256(
                (_ROOT / "docs" / platform["campaign_report"]).read_bytes().replace(b"\n", b"\r\n")
                if platform["runner"] == "windows-latest"
                else (_ROOT / "docs" / platform["campaign_report"]).read_bytes()
            ).hexdigest()
            == platform["campaign_report_sha256"]
            for platform in report["platforms"]
        )
    )


def test_vm_decoder_platform_campaign_records_recoverable_parser_warnings() -> None:
    report = json.loads(_VM_DECODER_PLATFORM_REPORT.read_text(encoding="utf-8"))

    expect(
        all(
            platform["parser_diagnostic_counts"] == {"macho_load_commands.warning": 103}
            for platform in report["platforms"]
        )
    )


def test_vm_decoder_platform_campaign_does_not_expose_host_paths() -> None:
    report = json.loads(_VM_DECODER_PLATFORM_REPORT.read_text(encoding="utf-8"))
    text = _VM_DECODER_PLATFORM_REPORT.read_text(encoding="utf-8")
    text += "".join(
        (_ROOT / "docs" / platform["campaign_report"]).read_text(encoding="utf-8") for platform in report["platforms"]
    )

    expect(not any(prefix in text for prefix in _HOST_PATH_PREFIXES))
