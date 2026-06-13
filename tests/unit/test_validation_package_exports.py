"""Contract tests for validation package exports."""

from r2morph.validation import BinaryDiffer as ExportedBinaryDiffer
from r2morph.validation import ByteDiff as ExportedByteDiff
from r2morph.validation import ChangeSeverity as ExportedChangeSeverity
from r2morph.validation import DiffReport as ExportedDiffReport
from r2morph.validation import DiffType as ExportedDiffType
from r2morph.validation import FunctionDiff as ExportedFunctionDiff
from r2morph.validation import SectionDiff as ExportedSectionDiff


def test_validation_package_exports_diff_models() -> None:
    """The validation package should re-export diff models."""
    exported_values = {
        "diff_type": ExportedDiffType.SECTION_MODIFIED.value,
        "severity": ExportedChangeSeverity.MEDIUM.value,
        "byte_offset": ExportedByteDiff(offset=1, original=b"a", mutated=b"b").offset,
        "section_name": ExportedSectionDiff(name=".text").name,
        "function_address": ExportedFunctionDiff(name="func", address=1).address,
        "report_binary": ExportedDiffReport(original_binary="a", mutated_binary="b").original_binary,
    }
    assert exported_values == {
        "diff_type": "section_modified",
        "severity": "medium",
        "byte_offset": 1,
        "section_name": ".text",
        "function_address": 1,
        "report_binary": "a",
    }


def test_validation_package_exports_binary_differ() -> None:
    """The validation package should re-export BinaryDiffer."""
    assert ExportedBinaryDiffer is not None
