"""Contract tests for report command I/O helpers."""

from __future__ import annotations

import json
from pathlib import Path

from r2morph.reporting.report_command_io import emit_report_output, load_report_payload


def test_report_command_io_contract(tmp_path: Path) -> None:
    report_file = tmp_path / "report.json"
    report_file.write_text('{"mutations": [], "validations": [], "binary_path": "sample.bin"}', encoding="utf-8")

    assert load_report_payload(report_file)["binary_path"] == "sample.bin"

    out_file = tmp_path / "out.sarif"
    emit_report_output("sarif", out_file, [{"id": 1}], [{"id": 2}], "sample.bin")

    sarif = json.loads(out_file.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0" and sarif["runs"]
