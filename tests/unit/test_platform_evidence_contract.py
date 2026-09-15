from __future__ import annotations

from pathlib import Path

from scripts.platform_evidence import summarize_platform_reports
from tests.utils.assertions import expect


def _write_report(path: Path, case_name: str, *, skipped: bool = False) -> None:
    skipped_node = "<skipped message='unavailable'/>" if skipped else ""
    path.write_text(
        f"<testsuite tests='1'><testcase name='{case_name}'>{skipped_node}</testcase></testsuite>",
        encoding="utf-8",
    )


def test_platform_evidence_reports_complete_and_incomplete_targets(tmp_path: Path) -> None:
    for platform_name in ("macos-arm64", "windows-pe", "elf-arm64"):
        (tmp_path / platform_name).mkdir()
    _write_report(
        tmp_path / "macos-arm64" / "report.xml",
        "test_nop_insertion_arm64_preserves_native_output",
    )
    _write_report(tmp_path / "windows-pe" / "report.xml", "test_pe_handler_checksum", skipped=True)
    _write_report(
        tmp_path / "elf-arm64" / "report.xml",
        "test_elf_arm64_nop_insertion_preserves_native_exit_code",
    )

    report = summarize_platform_reports(tmp_path)

    expect(
        report["summary"]["status"] == "incomplete"
        and report["platforms"]["macos-arm64"]["status"] == "complete"
        and report["platforms"]["windows-pe"]["status"] == "incomplete"
        and report["summary"]["incomplete_platforms"] == ["windows-pe"]
    )
