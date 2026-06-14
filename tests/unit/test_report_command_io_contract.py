"""Contract tests for report command I/O helpers."""

from __future__ import annotations

from pathlib import Path

from r2morph.reporting.report_command_io import emit_report_output, load_report_payload


def test_report_command_io_contract(tmp_path: Path, monkeypatch) -> None:
    report_file = tmp_path / "report.json"
    report_file.write_text('{"mutations": [], "validations": [], "binary_path": "sample.bin"}', encoding="utf-8")

    assert load_report_payload(report_file)["binary_path"] == "sample.bin"

    emitted = []

    class _SarifReport:
        def to_json(self) -> str:
            return "{\"sarif\": true}"

    monkeypatch.setattr(
        "r2morph.reporting.sarif_formatter.format_as_sarif",
        lambda mutations, validations, binary_path: emitted.append((mutations, validations, binary_path)) or _SarifReport(),
    )

    out_file = tmp_path / "out.sarif"
    emit_report_output("sarif", out_file, [{"id": 1}], [{"id": 2}], "sample.bin")

    assert emitted == [([{"id": 1}], [{"id": 2}], "sample.bin")]
    assert out_file.read_text(encoding="utf-8") == "{\"sarif\": true}"
