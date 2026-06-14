from pathlib import Path

from r2morph.reporting.report_output_io import emit_report_payload


def test_report_output_io_contract(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    emit_report_payload(filtered_payload={"mutations": []}, output=output, summary_only=True)
    assert output.exists()
