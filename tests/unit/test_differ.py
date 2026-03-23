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
from unittest.mock import MagicMock

from r2morph.validation.differ import (
    DiffType,
    ChangeSeverity,
    ByteDiff,
    SectionDiff,
    FunctionDiff,
    BinaryDiff,
    DiffReport,
    BinaryDiffer,
    compare_binaries,
)


class TestByteDiff:
    """Test ByteDiff dataclass."""

    def test_basic_bytediff(self):
        """Test basic byte difference."""
        diff = ByteDiff(
            offset=0x1000,
            original=b"\x90",
            mutated=b"\xcc",
        )
        assert diff.offset == 0x1000
        assert diff.original == b"\x90"
        assert diff.mutated == b"\xcc"

    def test_bytediff_with_context(self):
        """Test byte difference with context."""
        diff = ByteDiff(
            offset=0x1000,
            original=b"\x90",
            mutated=b"\xcc",
            context_before=b"\x48\x89\xe5",
            context_after=b"\x48\x83\xc4",
        )
        assert diff.context_before == b"\x48\x89\xe5"
        assert diff.context_after == b"\x48\x83\xc4"

    def test_bytediff_to_dict(self):
        """Test byte difference serialization."""
        diff = ByteDiff(
            offset=0x1000,
            original=b"\x90",
            mutated=b"\xcc",
            context_before=b"\x48\x89",
        )
        d = diff.to_dict()
        assert d["offset"] == "0x1000"
        assert d["original"] == "90"
        assert d["mutated"] == "cc"
        assert d["context_before"] == "4889"


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
        assert diff.name == ".text"
        assert diff.original_size == 0x1000
        assert diff.mutated_size == 0x1200

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
        assert len(diff.byte_diffs) == 2

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
        assert d["name"] == ".text"
        assert d["original_address"] == "0x1000"
        assert d["mutated_address"] == "0x1100"


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
        assert diff.name == "main"
        assert diff.address == 0x1000
        assert diff.original_size == 0x50

    def test_functiondiff_with_bytes(self):
        """Test function difference with bytes."""
        diff = FunctionDiff(
            name="main",
            address=0x1000,
            original_bytes=b"\x48\x89\xe5" + b"\x90" * 10,
            mutated_bytes=b"\x55\x48\x89\xe5" + b"\x90" * 10,
        )
        assert len(diff.original_bytes) == 13
        assert len(diff.mutated_bytes) == 14

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
        assert d["name"] == "main"
        assert d["address"] == "0x1000"
        assert d["byte_diff_count"] == 1
        assert d["disassembly_diff_count"] == 1


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
        assert diff.diff_type == DiffType.SECTION_MODIFIED
        assert diff.severity == ChangeSeverity.MEDIUM

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
        assert d["diff_type"] == "function_modified"
        assert d["severity"] == "low"
        assert d["byte_diff_count"] == 5


class TestDiffReport:
    """Test DiffReport."""

    def test_empty_report(self):
        """Test empty report."""
        report = DiffReport(
            original_binary="/bin/original",
            mutated_binary="/bin/mutated",
        )
        assert len(report.diffs) == 0

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
        assert len(report.diffs) == 1

    def test_to_json(self):
        """Test JSON serialization."""
        report = DiffReport(
            original_binary="/bin/original",
            mutated_binary="/bin/mutated",
            diffs=[],
        )
        json_str = report.to_json()
        assert '"original_binary"' in json_str
        assert '"diffs": []' in json_str

    def test_write_report(self, tmp_path):
        """Test writing report to file."""
        report = DiffReport(
            original_binary="/bin/original",
            mutated_binary="/bin/mutated",
            diffs=[],
        )
        report_path = tmp_path / "report.json"
        report.write_report(report_path)
        assert report_path.exists()

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
        assert len(by_severity[ChangeSeverity.LOW]) == 1
        assert len(by_severity[ChangeSeverity.CRITICAL]) == 1

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
        assert report.summary["total_changes"] == 2
        assert report.summary["total_byte_diffs"] == 15
        assert report.summary["by_severity"]["medium"] == 1
        assert report.summary["by_severity"]["low"] == 1


class TestBinaryDiffer:
    """Test BinaryDiffer comparison operations."""

    def _create_mock_binary(self, path="/bin/test"):
        """Create a mock binary object."""
        binary = MagicMock()
        binary.path = Path(path)
        binary.is_analyzed.return_value = True
        binary.get_sections.return_value = []
        binary.get_functions.return_value = []
        binary.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}
        binary.read_bytes.return_value = b"\x90" * 100
        return binary

    def test_compare_empty(self):
        """Test comparison with no differences."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        original.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
        ]
        mutated.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        # Should have header check but no section diffs
        assert isinstance(report, DiffReport)

    def test_compare_sections_added(self):
        """Test section added detection."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        original.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
        ]
        mutated.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
            {"name": ".added", "addr": 0x2000, "size": 0x500},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        section_added = [d for d in report.diffs if d.diff_type == DiffType.SECTION_ADDED]
        assert len(section_added) == 1
        assert ".added" in section_added[0].description

    def test_compare_sections_removed(self):
        """Test section removed detection."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        original.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
            {"name": ".removed", "addr": 0x2000, "size": 0x500},
        ]
        mutated.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        section_removed = [d for d in report.diffs if d.diff_type == DiffType.SECTION_REMOVED]
        assert len(section_removed) == 1
        assert ".removed" in section_removed[0].description

    def test_compare_sections_modified(self):
        """Test section modified detection."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        original.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 0x1000},
        ]
        mutated.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 0x1200},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        section_modified = [d for d in report.diffs if d.diff_type == DiffType.SECTION_MODIFIED]
        assert len(section_modified) == 1

    def test_compare_functions_added(self):
        """Test function added detection."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        original.get_functions.return_value = [
            {"offset": 0x1000, "name": "main", "size": 0x50},
        ]
        mutated.get_functions.return_value = [
            {"offset": 0x1000, "name": "main", "size": 0x50},
            {"offset": 0x2000, "name": "added_func", "size": 0x30},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        func_added = [d for d in report.diffs if d.diff_type == DiffType.FUNCTION_ADDED]
        assert len(func_added) == 1

    def test_compare_functions_removed(self):
        """Test function removed detection."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        original.get_functions.return_value = [
            {"offset": 0x1000, "name": "main", "size": 0x50},
            {"offset": 0x2000, "name": "removed_func", "size": 0x30},
        ]
        mutated.get_functions.return_value = [
            {"offset": 0x1000, "name": "main", "size": 0x50},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        func_removed = [d for d in report.diffs if d.diff_type == DiffType.FUNCTION_REMOVED]
        assert len(func_removed) == 1

    def test_compare_functions_modified(self):
        """Test function modified detection."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        original.get_functions.return_value = [
            {"offset": 0x1000, "name": "main", "size": 0x50},
        ]
        mutated.get_functions.return_value = [
            {"offset": 0x1000, "name": "main", "size": 0x70},
        ]

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        func_modified = [d for d in report.diffs if d.diff_type == DiffType.FUNCTION_MODIFIED]
        assert len(func_modified) == 1

    def test_compare_architecture_change(self):
        """Test architecture change detection."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        original.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}
        mutated.get_arch_info.return_value = {"arch": "arm64", "bits": 64}

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        arch_changed = [d for d in report.diffs if d.diff_type == DiffType.HEADER_MODIFIED]
        assert len(arch_changed) >= 1
        assert any("Architecture" in d.description for d in arch_changed)

    def test_compare_bits_change(self):
        """Test bits change detection."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        original.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}
        mutated.get_arch_info.return_value = {"arch": "x86_64", "bits": 32}

        differ = BinaryDiffer(original, mutated)
        report = differ.compare()

        bits_changed = [d for d in report.diffs if d.diff_type == DiffType.HEADER_MODIFIED]
        assert any("Bits" in d.description for d in bits_changed)

    def test_compare_section_bytes(self):
        """Test section byte comparison."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        # Sections have same address but different sizes to trigger modification
        original.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 20},
        ]
        mutated.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 21},
        ]
        original.read_bytes.return_value = b"\x90" * 20
        mutated.read_bytes.return_value = b"\xcc" * 20

        differ = BinaryDiffer(original, mutated, context_bytes=2)
        report = differ.compare()

        # Should detect section modified due to size change
        section_modified = [d for d in report.diffs if d.diff_type == DiffType.SECTION_MODIFIED]
        assert len(section_modified) >= 1

    def test_context_bytes(self):
        """Test context bytes in diff."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        original.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 12},
        ]
        mutated.get_sections.return_value = [
            {"name": ".text", "addr": 0x1000, "size": 12},
        ]
        original.read_bytes.return_value = b"AAAABBBBCCCC"
        mutated.read_bytes.return_value = b"AAAAXBBBCCCC"

        differ = BinaryDiffer(original, mutated, context_bytes=3)
        report = differ.compare()

        for diff in report.diffs:
            for section_diff in diff.section_diffs:
                for byte_diff in section_diff.byte_diffs:
                    assert len(byte_diff.context_before) <= 3

    def test_get_function_diff(self):
        """Test getting function-specific diff."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        # get_function_diff uses read_bytes and get_function_disasm (not get_function_bytes)
        original.read_bytes.return_value = b"\x90" * 10
        mutated.read_bytes.return_value = b"\xcc" * 10
        original.get_function_disasm.return_value = [
            {"offset": 0x1000, "size": 1, "disasm": "nop"},
            {"offset": 0x1001, "size": 9, "disasm": "nop"},
        ]
        mutated.get_function_disasm.return_value = [
            {"offset": 0x1000, "size": 1, "disasm": "int3"},
            {"offset": 0x1001, "size": 9, "disasm": "int3"},
        ]
        mutated.get_functions.return_value = [
            {"offset": 0x1000, "name": "test_func"},
        ]

        differ = BinaryDiffer(original, mutated)
        func_diff = differ.get_function_diff(0x1000)

        assert func_diff is not None
        assert func_diff.name == "test_func"
        assert len(func_diff.byte_diffs) == 10

    def test_get_function_diff_none(self):
        """Test getting function diff when not available."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        # get_function_diff returns None when disasm is empty
        original.get_function_disasm.return_value = []
        mutated.get_function_disasm.return_value = []

        differ = BinaryDiffer(original, mutated)
        func_diff = differ.get_function_diff(0x1000)

        assert func_diff is None

    def test_compute_byte_diffs_size_diff(self):
        """Test byte diffs with size difference."""
        original = self._create_mock_binary("/bin/original")
        mutated = self._create_mock_binary("/bin/mutated")

        differ = BinaryDiffer(original, mutated)
        diffs = differ._compute_byte_diffs(b"\x90\x90\x90", b"\x90\x90\x90\x90", 0x1000)

        assert len(diffs) >= 1
        last_diff = diffs[-1]
        assert last_diff.offset >= 0x1000


class TestCompareBinaries:
    """Test the compare_binaries convenience function."""

    def test_compare_binaries_function(self):
        """Test compare_binaries function."""
        original = MagicMock()
        original.path = Path("/bin/original")
        original.is_analyzed.return_value = True
        original.get_sections.return_value = []
        original.get_functions.return_value = []
        original.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        mutated = MagicMock()
        mutated.path = Path("/bin/mutated")
        mutated.is_analyzed.return_value = True
        mutated.get_sections.return_value = []
        mutated.get_functions.return_value = []
        mutated.get_arch_info.return_value = {"arch": "x86_64", "bits": 64}

        report = compare_binaries(original, mutated)

        assert isinstance(report, DiffReport)
        assert report.original_binary == "/bin/original"
        assert report.mutated_binary == "/bin/mutated"


class TestDiffTypes:
    """Test all diff types."""

    def test_all_diff_types_exist(self):
        """Test all diff types are defined."""
        assert DiffType.SECTION_ADDED.value == "section_added"
        assert DiffType.SECTION_REMOVED.value == "section_removed"
        assert DiffType.SECTION_MODIFIED.value == "section_modified"
        assert DiffType.FUNCTION_ADDED.value == "function_added"
        assert DiffType.FUNCTION_REMOVED.value == "function_removed"
        assert DiffType.FUNCTION_MODIFIED.value == "function_modified"
        assert DiffType.BYTES_CHANGED.value == "bytes_changed"
        assert DiffType.SYMBOL_ADDED.value == "symbol_added"
        assert DiffType.SYMBOL_REMOVED.value == "symbol_removed"
        assert DiffType.SYMBOL_MODIFIED.value == "symbol_modified"
        assert DiffType.IMPORT_ADDED.value == "import_added"
        assert DiffType.IMPORT_REMOVED.value == "import_removed"
        assert DiffType.EXPORT_ADDED.value == "export_added"
        assert DiffType.EXPORT_REMOVED.value == "export_removed"
        assert DiffType.HEADER_MODIFIED.value == "header_modified"

    def test_all_severity_levels(self):
        """Test all severity levels."""
        assert ChangeSeverity.INFORMATIONAL.value == "informational"
        assert ChangeSeverity.LOW.value == "low"
        assert ChangeSeverity.MEDIUM.value == "medium"
        assert ChangeSeverity.HIGH.value == "high"
        assert ChangeSeverity.CRITICAL.value == "critical"
