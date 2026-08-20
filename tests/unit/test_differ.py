"""
Tests for binary differ module.

Covers:
- ByteDiff dataclass
- SectionDiff dataclass
- FunctionDiff dataclass
- BinaryDiff dataclass
- DiffReport generation
- BinaryDiffer comparison operations
"""

from pathlib import Path
from typing import Any

from r2morph.validation.differ import (
    BinaryDiff,
    BinaryDiffer,
    ByteDiff,
    ChangeSeverity,
    DiffReport,
    DiffType,
    FunctionDiff,
    SectionDiff,
    compare_binaries,
)
from tests.utils.assertions import expect

_EXPECTED_DIFF_ADDRESS_4096 = 0x1000
_EXPECTED_DIFF_MUTATED_SIZE_4608 = 0x1200
_EXPECTED_DIFF_OFFSET_4096 = 0x1000
_EXPECTED_DIFF_ORIGINAL_SIZE_4096 = 0x1000
_EXPECTED_DIFF_ORIGINAL_SIZE_80 = 0x50
_EXPECTED_D_BYTE_DIFF_COUNT_5 = 5
_EXPECTED_LAST_DIFF_OFFSET_4096 = 0x1000
_EXPECTED_LEN_BYTE_DIFF_CONTEXT_BEFORE_3 = 3
_EXPECTED_LEN_DIFF_BYTE_DIFFS_2 = 2
_EXPECTED_LEN_DIFF_MUTATED_BYTES_14 = 14
_EXPECTED_LEN_DIFF_ORIGINAL_BYTES_13 = 13
_EXPECTED_LEN_FUNC_DIFF_BYTE_DIFFS_10 = 10
_EXPECTED_REPORT_SUMMARY_TOTAL_BYTE_DIFFS_15 = 15
_EXPECTED_REPORT_SUMMARY_TOTAL_CHANGES_2 = 2


class _Binary:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.sections: list[dict[str, Any]] = []
        self.functions: list[dict[str, Any]] = []
        self.arch_info: dict[str, Any] = {"arch": "x86_64", "bits": 64}
        self.contents = b"\x90" * 100
        self.disassembly: list[dict[str, Any]] = []

    def is_analyzed(self) -> bool:
        return True

    def get_sections(self) -> list[dict[str, Any]]:
        return self.sections

    def get_functions(self) -> list[dict[str, Any]]:
        return self.functions

    def get_arch_info(self) -> dict[str, Any]:
        return self.arch_info

    def read_bytes(self, address: int, size: int) -> bytes:
        return self.contents[:size]

    def get_function_disasm(self, address: int) -> list[dict[str, Any]]:
        return self.disassembly


class TestByteDiff:
    """Test ByteDiff dataclass."""

    def test_basic_bytediff(self):
        """Test basic byte difference."""
        diff = ByteDiff(
            offset=0x1000,
            original=b"\x90",
            mutated=b"\xcc",
        )
        expect(diff.offset == _EXPECTED_DIFF_OFFSET_4096)
        expect(diff.original == b"\x90")
        expect(diff.mutated == b"\xcc")

    def test_bytediff_with_context(self):
        """Test byte difference with context."""
        diff = ByteDiff(
            offset=0x1000,
            original=b"\x90",
            mutated=b"\xcc",
            context_before=b"\x48\x89\xe5",
            context_after=b"\x48\x83\xc4",
        )
        expect(diff.context_before == b"H\x89\xe5")
        expect(diff.context_after == b"H\x83\xc4")

    def test_bytediff_to_dict(self):
        """Test byte difference serialization."""
        diff = ByteDiff(
            offset=0x1000,
            original=b"\x90",
            mutated=b"\xcc",
            context_before=b"\x48\x89",
        )
        d = diff.to_dict()
        expect(d["offset"] == "0x1000")
        expect(d["original"] == "90")
        expect(d["mutated"] == "cc")
        expect(d["context_before"] == "4889")


class TestSectionDiff:
    """Test SectionDiff dataclass."""

    def test_basic_sectiondiff(self):
        """Test basic section difference."""
        diff = SectionDiff(
            name=".text",
            original_address=0x1000,
            mutated_address=0x1000,
            original_size=0x1000,
            mutated_size=0x1200,
        )
        expect(diff.name == ".text")
        expect(diff.original_size == _EXPECTED_DIFF_ORIGINAL_SIZE_4096)
        expect(diff.mutated_size == _EXPECTED_DIFF_MUTATED_SIZE_4608)

    def test_sectiondiff_with_byte_diffs(self):
        """Test section difference with byte diffs."""
        byte_diffs = [
            ByteDiff(offset=0x1000, original=b"\x90", mutated=b"\xcc"),
            ByteDiff(offset=0x1001, original=b"\x90", mutated=b"\xcc"),
        ]
        diff = SectionDiff(
            name=".text",
            byte_diffs=byte_diffs,
        )
        expect(len(diff.byte_diffs) == _EXPECTED_LEN_DIFF_BYTE_DIFFS_2)

    def test_sectiondiff_to_dict(self):
        """Test section difference serialization."""
        diff = SectionDiff(
            name=".text",
            original_address=0x1000,
            mutated_address=0x1100,
            original_permissions="rx",
            mutated_permissions="rwx",
        )
        d = diff.to_dict()
        expect(d["name"] == ".text")
        expect(d["original_address"] == "0x1000")
        expect(d["mutated_address"] == "0x1100")


class TestFunctionDiff:
    """Test FunctionDiff dataclass."""

    def test_basic_functiondiff(self):
        """Test basic function difference."""
        diff = FunctionDiff(
            name="main",
            address=0x1000,
            original_size=0x50,
            mutated_size=0x60,
        )
        expect(diff.name == "main")
        expect(diff.address == _EXPECTED_DIFF_ADDRESS_4096)
        expect(diff.original_size == _EXPECTED_DIFF_ORIGINAL_SIZE_80)

    def test_functiondiff_with_bytes(self):
        """Test function difference with bytes."""
        diff = FunctionDiff(
            name="main",
            address=0x1000,
            original_bytes=b"\x48\x89\xe5" + b"\x90" * 10,
            mutated_bytes=b"\x55\x48\x89\xe5" + b"\x90" * 10,
        )
        expect(len(diff.original_bytes) == _EXPECTED_LEN_DIFF_ORIGINAL_BYTES_13)
        expect(len(diff.mutated_bytes) == _EXPECTED_LEN_DIFF_MUTATED_BYTES_14)

    def test_functiondiff_to_dict(self):
        """Test function difference serialization."""
        diff = FunctionDiff(
            name="main",
            address=0x1000,
            original_size=0x50,
            mutated_size=0x60,
            byte_diffs=[ByteDiff(offset=0x1000, original=b"\x90", mutated=b"\xcc")],
            disassembly_diff=[(0x1000, "nop", "int3")],
        )
        d = diff.to_dict()
        expect(d["name"] == "main")
        expect(d["address"] == "0x1000")
        expect(d["byte_diff_count"] == 1)
        expect(d["disassembly_diff_count"] == 1)


class TestBinaryDiff:
    """Test BinaryDiff dataclass."""

    def test_section_modified_diff(self):
        """Test section modified diff."""
        diff = BinaryDiff(
            original_path="/bin/original",
            mutated_path="/bin/mutated",
            diff_type=DiffType.SECTION_MODIFIED,
            severity=ChangeSeverity.MEDIUM,
            description="Section .text modified",
        )
        expect(diff.diff_type == DiffType.SECTION_MODIFIED)
        expect(diff.severity == ChangeSeverity.MEDIUM)

    def test_binary_diff_to_dict(self):
        """Test binary diff serialization."""
        diff = BinaryDiff(
            original_path="/bin/original",
            mutated_path="/bin/mutated",
            diff_type=DiffType.FUNCTION_MODIFIED,
            severity=ChangeSeverity.LOW,
            description="Function size changed",
            byte_diff_count=5,
        )
        d = diff.to_dict()
        expect(d["diff_type"] == "function_modified")
        expect(d["severity"] == "low")
        expect(d["byte_diff_count"] == _EXPECTED_D_BYTE_DIFF_COUNT_5)


class TestDiffReport:
    """Test DiffReport."""

    def test_empty_report(self):
        """Test empty report."""
        report = DiffReport(
            original_binary="/bin/original",
            mutated_binary="/bin/mutated",
        )
        expect(len(report.diffs) == 0)

    def test_report_with_diffs(self):
        """Test report with diffs."""
        report = DiffReport(
            original_binary="/bin/original",
            mutated_binary="/bin/mutated",
            diffs=[
                BinaryDiff(
                    original_path="/bin/original",
                    mutated_path="/bin/mutated",
                    diff_type=DiffType.SECTION_ADDED,
                    severity=ChangeSeverity.MEDIUM,
                    description="Section added",
                ),
            ],
        )
        expect(len(report.diffs) == 1)

    def test_to_json(self):
        """Test JSON serialization."""
        report = DiffReport(
            original_binary="/bin/original",
            mutated_binary="/bin/mutated",
            diffs=[],
        )
        json_str = report.to_json()
        expect(not ('"original_binary"' not in json_str))
        expect(not ('"diffs": []' not in json_str))

    def test_write_report(self, tmp_path):
        """Test writing report to file."""
        report = DiffReport(
            original_binary="/bin/original",
            mutated_binary="/bin/mutated",
            diffs=[],
        )
        report_path = tmp_path / "report.json"
        report.write_report(report_path)
        expect(report_path.exists())

    def test_get_changes_by_severity(self):
        """Test grouping changes by severity."""
        report = DiffReport(
            original_binary="/bin/original",
            mutated_binary="/bin/mutated",
            diffs=[
                BinaryDiff(
                    original_path="/bin/original",
                    mutated_path="/bin/mutated",
                    diff_type=DiffType.BYTES_CHANGED,
                    severity=ChangeSeverity.LOW,
                    description="Minor change",
                ),
                BinaryDiff(
                    original_path="/bin/original",
                    mutated_path="/bin/mutated",
                    diff_type=DiffType.SECTION_REMOVED,
                    severity=ChangeSeverity.CRITICAL,
                    description="Critical section removed",
                ),
            ],
        )
        by_severity = report.get_changes_by_severity()
        expect(len(by_severity[ChangeSeverity.LOW]) == 1)
        expect(len(by_severity[ChangeSeverity.CRITICAL]) == 1)

    def test_compute_summary(self):
        """Test summary computation."""
        report = DiffReport(
            original_binary="/bin/original",
            mutated_binary="/bin/mutated",
            diffs=[
                BinaryDiff(
                    original_path="/bin/original",
                    mutated_path="/bin/mutated",
                    diff_type=DiffType.SECTION_MODIFIED,
                    severity=ChangeSeverity.MEDIUM,
                    description="Section modified",
                    byte_diff_count=10,
                ),
                BinaryDiff(
                    original_path="/bin/original",
                    mutated_path="/bin/mutated",
                    diff_type=DiffType.FUNCTION_MODIFIED,
                    severity=ChangeSeverity.LOW,
                    description="Function modified",
                    byte_diff_count=5,
                ),
            ],
        )
        report._compute_summary()
        expect(report.summary["total_changes"] == _EXPECTED_REPORT_SUMMARY_TOTAL_CHANGES_2)
        expect(report.summary["total_byte_diffs"] == _EXPECTED_REPORT_SUMMARY_TOTAL_BYTE_DIFFS_15)
        expect(report.summary["by_severity"]["medium"] == 1)
        expect(report.summary["by_severity"]["low"] == 1)


class TestBinaryDiffer:
    """Test BinaryDiffer comparison operations."""

    def _create_binary(self, path: str = "/bin/test") -> _Binary:
        return _Binary(path)

    def test_compare_empty(self):
        """Test comparison with no differences."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        original.sections = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
        ]
        mutated.sections = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        # Should have header check but no section diffs
        expect(isinstance(report, DiffReport))

    def test_compare_sections_added(self):
        """Test section added detection."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        original.sections = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
        ]
        mutated.sections = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
            {"name": ".added", "addr": 0x2000, "size": 0x500},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        section_added = [d for d in report.diffs if d.diff_type == DiffType.SECTION_ADDED]
        expect(len(section_added) == 1)
        expect(not (".added" not in section_added[0].description))

    def test_compare_sections_removed(self):
        """Test section removed detection."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        original.sections = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
            {"name": ".removed", "addr": 0x2000, "size": 0x500},
        ]
        mutated.sections = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        section_removed = [d for d in report.diffs if d.diff_type == DiffType.SECTION_REMOVED]
        expect(len(section_removed) == 1)
        expect(not (".removed" not in section_removed[0].description))

    def test_compare_sections_modified(self):
        """Test section modified detection."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        original.sections = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
        ]
        mutated.sections = [
            {"name": ".text", "addr": 0x1000, "size": 0x1200},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        section_modified = [d for d in report.diffs if d.diff_type == DiffType.SECTION_MODIFIED]
        expect(len(section_modified) == 1)

    def test_compare_functions_added(self):
        """Test function added detection."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        original.functions = [
            {"offset": 0x1000, "name": "main", "size": 0x50},
        ]
        mutated.functions = [
            {"offset": 0x1000, "name": "main", "size": 0x50},
            {"offset": 0x2000, "name": "added_func", "size": 0x30},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        func_added = [d for d in report.diffs if d.diff_type == DiffType.FUNCTION_ADDED]
        expect(len(func_added) == 1)

    def test_compare_functions_removed(self):
        """Test function removed detection."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        original.functions = [
            {"offset": 0x1000, "name": "main", "size": 0x50},
            {"offset": 0x2000, "name": "removed_func", "size": 0x30},
        ]
        mutated.functions = [
            {"offset": 0x1000, "name": "main", "size": 0x50},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        func_removed = [d for d in report.diffs if d.diff_type == DiffType.FUNCTION_REMOVED]
        expect(len(func_removed) == 1)

    def test_compare_functions_modified(self):
        """Test function modified detection."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        original.functions = [
            {"offset": 0x1000, "name": "main", "size": 0x50},
        ]
        mutated.functions = [
            {"offset": 0x1000, "name": "main", "size": 0x70},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        func_modified = [d for d in report.diffs if d.diff_type == DiffType.FUNCTION_MODIFIED]
        expect(len(func_modified) == 1)

    def test_compare_architecture_change(self):
        """Test architecture change detection."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        original.arch_info = {"arch": "x86_64", "bits": 64}
        mutated.arch_info = {"arch": "arm64", "bits": 64}

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        arch_changed = [d for d in report.diffs if d.diff_type == DiffType.HEADER_MODIFIED]
        expect(not (len(arch_changed) < 1))
        expect(any("Architecture" in d.description for d in arch_changed))

    def test_compare_bits_change(self):
        """Test bits change detection."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        original.arch_info = {"arch": "x86_64", "bits": 64}
        mutated.arch_info = {"arch": "x86_64", "bits": 32}

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        bits_changed = [d for d in report.diffs if d.diff_type == DiffType.HEADER_MODIFIED]
        expect(any("Bits" in d.description for d in bits_changed))

    def test_compare_section_bytes(self):
        """Test section byte comparison."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        # Sections have same address but different sizes to trigger modification
        original.sections = [
            {"name": ".text", "addr": 0x1000, "size": 20},
        ]
        mutated.sections = [
            {"name": ".text", "addr": 0x1000, "size": 21},
        ]
        original.contents = b"\x90" * 20
        mutated.contents = b"\xcc" * 20

        differ = BinaryDiffer(original, mutated, context_bytes=2)
        report = differ.compare()

        # Should detect section modified due to size change
        section_modified = [d for d in report.diffs if d.diff_type == DiffType.SECTION_MODIFIED]
        expect(not (len(section_modified) < 1))

    def test_context_bytes(self):
        """Test context bytes in diff."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        original.sections = [
            {"name": ".text", "addr": 0x1000, "size": 12},
        ]
        mutated.sections = [
            {"name": ".text", "addr": 0x1000, "size": 12},
        ]
        original.contents = b"AAAABBBBCCCC"
        mutated.contents = b"AAAAXBBBCCCC"

        differ = BinaryDiffer(original, mutated, context_bytes=3)
        report = differ.compare()

        for diff in report.diffs:
            for section_diff in diff.section_diffs:
                for byte_diff in section_diff.byte_diffs:
                    expect(not (len(byte_diff.context_before) > _EXPECTED_LEN_BYTE_DIFF_CONTEXT_BEFORE_3))

    def test_get_function_diff(self):
        """Test getting function-specific diff."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        # get_function_diff uses read_bytes and get_function_disasm (not get_function_bytes)
        original.contents = b"\x90" * 10
        mutated.contents = b"\xcc" * 10
        original.disassembly = [
            {"offset": 0x1000, "size": 1, "disasm": "nop"},
            {"offset": 0x1001, "size": 9, "disasm": "nop"},
        ]
        mutated.disassembly = [
            {"offset": 0x1000, "size": 1, "disasm": "int3"},
            {"offset": 0x1001, "size": 9, "disasm": "int3"},
        ]
        mutated.functions = [
            {"offset": 0x1000, "name": "test_func"},
        ]

        differ = BinaryDiffer(original, mutated)
        func_diff = differ.get_function_diff(0x1000)

        expect(func_diff is not None)
        expect(func_diff.name == "test_func")
        expect(len(func_diff.byte_diffs) == _EXPECTED_LEN_FUNC_DIFF_BYTE_DIFFS_10)

    def test_get_function_diff_none(self):
        """Test getting function diff when not available."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        # get_function_diff returns None when disasm is empty
        original.disassembly = []
        mutated.disassembly = []

        differ = BinaryDiffer(original, mutated)
        func_diff = differ.get_function_diff(0x1000)

        expect(not (func_diff is not None))

    def test_compute_byte_diffs_size_diff(self):
        """Test byte diffs with size difference."""
        original = self._create_binary("/bin/original")
        mutated = self._create_binary("/bin/mutated")

        differ = BinaryDiffer(original, mutated)
        diffs = differ._compute_byte_diffs(b"\x90\x90\x90", b"\x90\x90\x90\x90", 0x1000)

        expect(not (len(diffs) < 1))
        last_diff = diffs[-1]
        expect(not (last_diff.offset < _EXPECTED_LAST_DIFF_OFFSET_4096))


class TestCompareBinaries:
    """Test the compare_binaries convenience function."""

    def test_compare_binaries_function(self):
        """Test compare_binaries function."""
        original = _Binary("/bin/original")
        mutated = _Binary("/bin/mutated")

        report = compare_binaries(original, mutated)

        expect(isinstance(report, DiffReport))
        expect(report.original_binary == "/bin/original")
        expect(report.mutated_binary == "/bin/mutated")


class TestDiffTypes:
    """Test all diff types."""

    def test_all_diff_types_exist(self):
        """Test all diff types are defined."""
        expect(DiffType.SECTION_ADDED.value == "section_added")
        expect(DiffType.SECTION_REMOVED.value == "section_removed")
        expect(DiffType.SECTION_MODIFIED.value == "section_modified")
        expect(DiffType.FUNCTION_ADDED.value == "function_added")
        expect(DiffType.FUNCTION_REMOVED.value == "function_removed")
        expect(DiffType.FUNCTION_MODIFIED.value == "function_modified")
        expect(DiffType.BYTES_CHANGED.value == "bytes_changed")
        expect(DiffType.SYMBOL_ADDED.value == "symbol_added")
        expect(DiffType.SYMBOL_REMOVED.value == "symbol_removed")
        expect(DiffType.SYMBOL_MODIFIED.value == "symbol_modified")
        expect(DiffType.IMPORT_ADDED.value == "import_added")
        expect(DiffType.IMPORT_REMOVED.value == "import_removed")
        expect(DiffType.EXPORT_ADDED.value == "export_added")
        expect(DiffType.EXPORT_REMOVED.value == "export_removed")
        expect(DiffType.HEADER_MODIFIED.value == "header_modified")

    def test_all_severity_levels(self):
        """Test all severity levels."""
        expect(ChangeSeverity.INFORMATIONAL.value == "informational")
        expect(ChangeSeverity.LOW.value == "low")
        expect(ChangeSeverity.MEDIUM.value == "medium")
        expect(ChangeSeverity.HIGH.value == "high")
        expect(ChangeSeverity.CRITICAL.value == "critical")
