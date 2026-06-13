"""Contract tests for validation diff models."""

from pathlib import Path

from r2morph.validation.differ_models import (
    BinaryDiff,
    ByteDiff,
    ChangeSeverity,
    DiffReport,
    DiffType,
    FunctionDiff,
    SectionDiff,
)


def test_diff_report_serialization_roundtrip(tmp_path: Path) -> None:
    """Diff reports should serialize their model data without losing fields."""
    report = DiffReport(
        original_binary="orig.bin",
        mutated_binary="mut.bin",
        diffs=[
            BinaryDiff(
                original_path="orig.bin",
                mutated_path="mut.bin",
                diff_type=DiffType.SECTION_MODIFIED,
                severity=ChangeSeverity.MEDIUM,
                description="section changed",
                section_diffs=[
                    SectionDiff(
                        name=".text",
                        original_address=0x1000,
                        mutated_address=0x2000,
                        original_size=4,
                        mutated_size=6,
                        byte_diffs=[ByteDiff(offset=0x1001, original=b"\x90", mutated=b"\xcc")],
                    )
                ],
                function_diffs=[
                    FunctionDiff(
                        name="func",
                        address=0x1000,
                        original_size=4,
                        mutated_size=6,
                    )
                ],
                byte_diff_count=1,
            )
        ],
    )

    payload = report.to_dict()
    assert payload["original_binary"] == "orig.bin"
    assert payload["mutated_binary"] == "mut.bin"
    assert payload["diffs"][0]["diff_type"] == "section_modified"
    assert payload["diffs"][0]["severity"] == "medium"
    assert payload["diffs"][0]["section_diffs"][0]["name"] == ".text"

    output_path = tmp_path / "diff.json"
    report.write_report(output_path)
    assert output_path.read_text().strip().startswith("{")
