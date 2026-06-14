from pathlib import Path
from unittest.mock import MagicMock

from r2morph.validation.differ_comparison import build_diff_report, compare_functions, compare_header, compare_sections
from r2morph.validation.differ_models import ChangeSeverity, DiffType


def _binary(path: str) -> MagicMock:
    binary = MagicMock()
    binary.path = Path(path)
    binary.get_sections.return_value = []
    binary.get_functions.return_value = []
    binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}
    return binary


def test_differ_comparison_helpers_build_report_from_real_inputs() -> None:
    original = _binary("/bin/original")
    mutated = _binary("/bin/mutated")

    original.get_sections.return_value = [{"name": ".text", "addr": 0x1000, "size": 0x1000}]
    mutated.get_sections.return_value = [{"name": ".text", "addr": 0x1000, "size": 0x1200}]
    original.get_functions.return_value = [{"offset": 0x1000, "name": "main", "size": 0x50}]
    mutated.get_functions.return_value = [{"offset": 0x1000, "name": "main", "size": 0x70}]

    report = build_diff_report(original, mutated, context_bytes=4)

    assert report.original_binary == "/bin/original"
    assert report.mutated_binary == "/bin/mutated"
    assert any(diff.diff_type == DiffType.SECTION_MODIFIED for diff in report.diffs)
    assert any(diff.diff_type == DiffType.FUNCTION_MODIFIED for diff in report.diffs)
    assert report.summary["total_changes"] == len(report.diffs)


def test_differ_comparison_helpers_keep_expected_severities() -> None:
    original = _binary("/bin/original")
    mutated = _binary("/bin/mutated")

    original.get_sections.return_value = [{"name": ".removed", "addr": 0x1000, "size": 0x1000}]
    mutated.get_sections.return_value = [{"name": ".added", "addr": 0x1000, "size": 0x1000}]
    original.get_functions.return_value = [{"offset": 0x1000, "name": "main", "size": 0x50}]
    mutated.get_functions.return_value = [{"offset": 0x2000, "name": "added", "size": 0x30}]
    mutated.get_arch_info.return_value = {"arch": "arm64", "bits": 32}

    sections = compare_sections(original, mutated, context_bytes=2)
    functions = compare_functions(original, mutated)
    header = compare_header(original, mutated)

    assert any(diff.severity == ChangeSeverity.HIGH for diff in sections if diff.diff_type == DiffType.SECTION_REMOVED)
    assert any(diff.severity == ChangeSeverity.MEDIUM for diff in sections if diff.diff_type == DiffType.SECTION_ADDED)
    assert any(diff.diff_type == DiffType.FUNCTION_ADDED for diff in functions)
    assert len(header) == 2
