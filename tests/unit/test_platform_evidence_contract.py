from __future__ import annotations

from pathlib import Path

from scripts.platform_evidence import _PASS_CASES, _REQUIRED_CASES, summarize_platform_reports
from tests.utils.assertions import expect


def _write_report(path: Path, case_names: str | tuple[str, ...], *, skipped: bool = False) -> None:
    skipped_node = "<skipped message='unavailable'/>" if skipped else ""
    names = (case_names,) if isinstance(case_names, str) else case_names
    cases = "".join(f"<testcase name='{name}'>{skipped_node}</testcase>" for name in names)
    path.write_text(
        f"<testsuite tests='{len(names)}'>{cases}</testsuite>",
        encoding="utf-8",
    )


def test_platform_evidence_reports_complete_and_incomplete_targets(tmp_path: Path) -> None:
    for platform_name in _REQUIRED_CASES:
        (tmp_path / platform_name).mkdir()
    _write_report(
        tmp_path / "macos-arm64" / "report.xml",
        _REQUIRED_CASES["macos-arm64"],
    )
    _write_report(tmp_path / "windows-pe" / "report.xml", "test_pe_handler_checksum", skipped=True)
    _write_report(
        tmp_path / "elf-arm64" / "report.xml",
        _REQUIRED_CASES["elf-arm64"],
    )
    _write_report(
        tmp_path / "elf-x86-32" / "report.xml",
        _REQUIRED_CASES["elf-x86-32"],
    )
    _write_report(
        tmp_path / "elf-arm-32" / "report.xml",
        _REQUIRED_CASES["elf-arm-32"],
    )

    report = summarize_platform_reports(tmp_path)

    expect(
        report["summary"]["status"] == "incomplete"
        and report["platforms"]["macos-arm64"]["status"] == "complete"
        and report["platforms"]["windows-pe"]["status"] == "incomplete"
        and report["summary"]["incomplete_platforms"] == ["windows-pe"]
    )


def test_platform_evidence_publishes_pass_level_status(tmp_path: Path) -> None:
    for platform_name, required_cases in _REQUIRED_CASES.items():
        platform_dir = tmp_path / platform_name
        platform_dir.mkdir()
        _write_report(platform_dir / "report.xml", required_cases)

    report = summarize_platform_reports(tmp_path)

    expect(
        report["summary"]["status"] == "complete"
        and all(
            row["status"] == "complete"
            for platform in report["platforms"].values()
            for row in platform["pass_evidence"].values()
        )
        and set(report["platforms"]["elf-arm64"]["pass_evidence"]) == set(_PASS_CASES["elf-arm64"])
    )


def test_platform_evidence_rejects_report_missing_required_case(tmp_path: Path) -> None:
    for platform_name in _REQUIRED_CASES:
        (tmp_path / platform_name).mkdir()
    _write_report(
        tmp_path / "macos-arm64" / "report.xml",
        _REQUIRED_CASES["macos-arm64"][:-1],
    )
    _write_report(tmp_path / "windows-pe" / "report.xml", _REQUIRED_CASES["windows-pe"])
    _write_report(tmp_path / "elf-arm64" / "report.xml", _REQUIRED_CASES["elf-arm64"])

    report = summarize_platform_reports(tmp_path)

    expect(
        report["platforms"]["macos-arm64"]["status"] == "incomplete"
        and report["platforms"]["macos-arm64"]["missing_required_cases"] == [_REQUIRED_CASES["macos-arm64"][-1]]
    )


def test_platform_aggregate_checks_out_repository_before_summary() -> None:
    workflow = Path(".github/workflows/differential-corpus.yml").read_text(encoding="utf-8")
    aggregate = workflow.split("  aggregate-platform-differential:", maxsplit=1)[1]
    checkout_index = aggregate.index("uses: actions/checkout@v5")
    setup_index = aggregate.index("uses: actions/setup-python@v6")
    dependency_index = aggregate.index('python -m pip install "defusedxml>=0.7.1"')
    script_index = aggregate.index("python scripts/platform_evidence.py")

    expect(checkout_index < script_index)
    expect(setup_index < dependency_index < script_index)


def test_platform_aggregate_fails_when_summary_is_incomplete() -> None:
    workflow = Path(".github/workflows/differential-corpus.yml").read_text(encoding="utf-8")
    aggregate = workflow.split("  aggregate-platform-differential:", maxsplit=1)[1]

    expect('report["summary"]["status"] != "complete"' in aggregate)
