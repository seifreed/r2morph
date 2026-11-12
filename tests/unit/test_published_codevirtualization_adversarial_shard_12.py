import json
from pathlib import Path, PurePosixPath

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _ROOT / "docs" / "protection-adversarial-codevirtualization-2026-11-12-4db66d94-shard-12.json"
_EXPECTED_FIXTURES = 9
_SHA256_HEX_LENGTH = 64
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
_PATH_MARKERS = (
    "/Users/",
    "/Applications/",
    "/private/",
    f"{PurePosixPath('/', 'tmp').as_posix()}/",
    "/home/",
)


def test_published_codevirtualization_shard_applies_without_partial_failures() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["fixture_shard"] == {"count": 16, "index": 12}
        and report["sample_count"] == _EXPECTED_FIXTURES
        and report["pass_names"] == ["CodeVirtualization"]
        and report["pass_summary"]["CodeVirtualization"]["applied"] == _EXPECTED_FIXTURES
        and report["pass_summary"]["CodeVirtualization"]["errors"] == 0
        and report["pass_summary"]["CodeVirtualization"]["unsupported_functions"] == 0
        and report["pass_summary"]["CodeVirtualization"]["partial_virtualization"] == 0
    )


def test_published_codevirtualization_shard_completes_available_analyzers() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    summary = report["summary"]

    expect(
        set(report["tool_summary"]) == _EXPECTED_TOOLS
        and summary["completed_tool_runs_by_tool"]["ida-pro"] == _EXPECTED_FIXTURES
        and summary["completed_tool_runs_by_tool"]["ghidra"] == _EXPECTED_FIXTURES
        and summary["completed_tool_runs_by_tool"]["angr"] == _EXPECTED_FIXTURES
        and summary["error_tool_runs"] == 0
        and summary["missing_tool_runs"] == 0
    )


def test_published_codevirtualization_shard_records_unavailable_analyzers() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["summary"]["unavailable_reasons_by_tool"]
        == {
            "binary-ninja": {"analyzer license is unavailable": _EXPECTED_FIXTURES},
            "triton": {"module 'triton' is unavailable": _EXPECTED_FIXTURES},
            "unicorn": {"the installed x86 emulator does not support an instruction in this fixture": 1},
        }
    )


def test_published_codevirtualization_shard_binds_commit_and_runner_output() -> None:
    report = json.loads(_REPORT.read_text(encoding="utf-8"))

    expect(
        report["source_commit"] == "4db66d94c64be03e5248053b8b84da9f59f58171"
        and len(report["runner_output_sha256"]) == _SHA256_HEX_LENGTH
        and report["execution_context"]
        == {
            "platform": "macOS arm64",
            "python": "3.13",
            "ida_pro": "9.5",
            "ghidra": "12.2",
            "radare2": "6.2.6",
        }
    )


def test_published_codevirtualization_shard_does_not_publish_analyst_paths() -> None:
    report_text = _REPORT.read_text(encoding="utf-8")

    expect(not any(marker in report_text for marker in _PATH_MARKERS))
