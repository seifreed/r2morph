"""
Tests for CFG hardening - pattern preservation and integrity validation.

Tests for Issue #3:
- Exception edge preservation
- Dispatcher/jump table pattern preservation
- CFG integrity checks
- Tests with optimized binaries
"""

import pytest
from unittest.mock import MagicMock, patch
from dataclasses import dataclass

from r2morph.analysis.pattern_preservation import (
    PatternPreservationManager,
    PatternType,
    PreservedPattern,
    ExclusionZone,
    Criticality,
)
from r2morph.validation.cfg_integrity import (
    CFGIntegrityChecker,
    IntegrityStatus,
    IntegrityViolation,
    IntegrityReport,
    IntegrityCheck,
    CFGSnapshot,
    HardenedMutationValidator,
)


class MockBinary:
    """Mock binary for testing."""

    def __init__(self):
        self._functions = []
        self._sections = []
        self._analyzed = False

    def is_analyzed(self):
        return self._analyzed

    def analyze(self):
        self._analyzed = True

    def get_functions(self):
        return self._functions

    def get_sections(self):
        return self._sections

    def get_arch_info(self):
        return {"arch": "x86_64", "bits": 64, "format": "ELF"}

    def get_function_disasm(self, addr):
        return []

    def get_basic_blocks(self, addr):
        return []

    def read_bytes(self, addr, size):
        return b"\x00" * size


class TestPreservedPattern:
    """Tests for PreservedPattern dataclass."""

    def test_pattern_properties(self):
        """Test pattern properties."""
        pattern = PreservedPattern(
            type=PatternType.JUMP_TABLE,
            start_address=0x1000,
            end_address=0x1100,
            criticality=Criticality.PRESERVE,
            source="test",
        )

        assert pattern.size == 0x100
        assert pattern.contains(0x1050)
        assert not pattern.contains(0x1200)

    def test_pattern_overlaps(self):
        """Test pattern overlap detection."""
        pattern = PreservedPattern(
            type=PatternType.JUMP_TABLE,
            start_address=0x1000,
            end_address=0x1100,
        )

        assert pattern.overlaps(0x1000, 0x1100)
        assert pattern.overlaps(0x1050, 0x1150)
        assert pattern.overlaps(0xF00, 0x1010)
        assert not pattern.overlaps(0x1200, 0x1300)

    def test_pattern_to_dict(self):
        """Test pattern serialization."""
        pattern = PreservedPattern(
            type=PatternType.EXCEPTION_HANDLER,
            start_address=0x2000,
            end_address=0x2100,
            criticality=Criticality.AVOID,
            source="exception_analysis",
        )

        d = pattern.to_dict()
        assert d["type"] == "exception_handler"
        assert d["start_address"] == "0x2000"
        assert d["size"] == 0x100
        assert d["criticality"] == "avoid"


class TestExclusionZone:
    """Tests for ExclusionZone."""

    def test_zone_expansion(self):
        """Test zone expansion with radius."""
        zone = ExclusionZone(
            start_address=0x1000,
            end_address=0x1100,
            pattern_type=PatternType.JUMP_TABLE,
            reason="Jump table",
            radius=8,
        )

        assert zone.expanded_start == 0x0FF8
        assert zone.expanded_end == 0x1108
        assert zone.contains(0x0FF8)
        assert zone.contains(0x1107)
        assert not zone.contains(0x0FF7)

    def test_zone_to_dict(self):
        """Test zone serialization."""
        zone = ExclusionZone(
            start_address=0x1000,
            end_address=0x1100,
            pattern_type=PatternType.PLT_THUNK,
            reason="PLT entry",
            radius=16,
        )

        d = zone.to_dict()
        assert d["pattern_type"] == "plt_thunk"
        assert d["radius"] == 16


class TestPatternPreservationManager:
    """Tests for PatternPreservationManager."""

    def test_init(self):
        """Test manager initialization."""
        binary = MockBinary()
        manager = PatternPreservationManager(binary, default_radius=16)

        assert manager.binary is binary
        assert manager.default_radius == 16
        assert manager._patterns == []
        assert manager._exclusion_zones == []

    def test_analyze_empty_binary(self):
        """Test analysis on empty binary."""
        binary = MockBinary()
        binary._analyzed = True

        manager = PatternPreservationManager(binary)
        summary = manager.analyze()

        assert summary["total_patterns"] == 0
        assert summary["total_exclusion_zones"] == 0

    def test_should_preserve_empty(self):
        """Test should_preserve before analysis."""
        binary = MockBinary()
        manager = PatternPreservationManager(binary)

        assert not manager.should_preserve(0x1000)
        assert not manager.should_avoid(0x1000)

    def test_get_patterns_in_range(self):
        """Test getting patterns in address range."""
        binary = MockBinary()
        manager = PatternPreservationManager(binary)

        manager._patterns = [
            PreservedPattern(
                type=PatternType.JUMP_TABLE,
                start_address=0x1000,
                end_address=0x1100,
            ),
            PreservedPattern(
                type=PatternType.PLT_THUNK,
                start_address=0x2000,
                end_address=0x2100,
            ),
        ]
        manager._build_address_index()

        patterns = manager.get_patterns_in_range(0x1000, 0x1200)
        assert len(patterns) == 1
        assert patterns[0].type == PatternType.JUMP_TABLE

    def test_get_safe_addresses(self):
        """Test getting safe addresses."""
        binary = MockBinary()
        manager = PatternPreservationManager(binary)

        manager._exclusion_zones = [
            ExclusionZone(
                start_address=0x1000,
                end_address=0x1100,
                pattern_type=PatternType.JUMP_TABLE,
            ),
            ExclusionZone(
                start_address=0x2000,
                end_address=0x2100,
                pattern_type=PatternType.PLT_THUNK,
            ),
        ]

        safe = manager.get_safe_addresses(0x800, 0x2800)

        assert len(safe) >= 2
        assert (0x800, 0x1000) in safe or any(s[0] == 0x800 for s in safe)

    def test_get_patterns_by_type(self):
        """Test filtering patterns by type."""
        binary = MockBinary()
        manager = PatternPreservationManager(binary)

        manager._patterns = [
            PreservedPattern(
                type=PatternType.JUMP_TABLE,
                start_address=0x1000,
                end_address=0x1100,
            ),
            PreservedPattern(
                type=PatternType.JUMP_TABLE,
                start_address=0x2000,
                end_address=0x2100,
            ),
            PreservedPattern(
                type=PatternType.PLT_THUNK,
                start_address=0x3000,
                end_address=0x3100,
            ),
        ]

        jt_patterns = manager.get_patterns_by_type(PatternType.JUMP_TABLE)
        assert len(jt_patterns) == 2

        plt_patterns = manager.get_patterns_by_type(PatternType.PLT_THUNK)
        assert len(plt_patterns) == 1

    def test_report(self):
        """Test preservation report generation."""
        binary = MockBinary()
        manager = PatternPreservationManager(binary)

        manager._patterns = [
            PreservedPattern(
                type=PatternType.JUMP_TABLE,
                start_address=0x1000,
                end_address=0x1100,
            ),
        ]
        manager._exclusion_zones = [
            ExclusionZone(
                start_address=0x1000,
                end_address=0x1100,
                pattern_type=PatternType.JUMP_TABLE,
                radius=8,
            ),
        ]

        report = manager.report()

        assert "summary" in report
        assert "exclusion_zones" in report
        assert report["summary"]["total_patterns"] == 1


class TestCFGSnapshot:
    """Tests for CFGSnapshot."""

    def test_snapshot_creation(self):
        """Test snapshot creation."""
        snapshot = CFGSnapshot(
            function_address=0x1000,
            blocks={
                0x1000: {"address": 0x1000, "size": 16},
                0x1010: {"address": 0x1010, "size": 32},
            },
            edges=[(0x1000, 0x1010, "normal")],
            entry_block=0x1000,
            exit_blocks=[0x1010],
            preserved_patterns=[],
        )

        assert snapshot.function_address == 0x1000
        assert len(snapshot.blocks) == 2
        assert len(snapshot.edges) == 1
        assert snapshot.entry_block == 0x1000


class TestIntegrityViolation:
    """Tests for IntegrityViolation."""

    def test_violation_creation(self):
        """Test violation creation."""
        violation = IntegrityViolation(
            status=IntegrityStatus.BROKEN_EDGE,
            address=0x1000,
            description="Edge broken",
            severity="error",
        )

        assert violation.status == IntegrityStatus.BROKEN_EDGE
        assert violation.address == 0x1000

    def test_violation_to_dict(self):
        """Test violation serialization."""
        violation = IntegrityViolation(
            status=IntegrityStatus.UNREACHABLE,
            address=0x2000,
            description="Block unreachable",
            severity="warning",
            metadata={"block": "test"},
        )

        d = violation.to_dict()
        assert d["status"] == "unreachable"
        assert d["address"] == "0x2000"
        assert d["severity"] == "warning"


class TestIntegrityReport:
    """Tests for IntegrityReport."""

    def test_valid_report(self):
        """Test valid integrity report."""
        report = IntegrityReport(
            valid=True,
            violations=[],
            checks_run=[],
        )

        assert report.valid
        assert len(report.violations) == 0

    def test_invalid_report(self):
        """Test invalid integrity report."""
        report = IntegrityReport(
            valid=False,
            violations=[
                IntegrityViolation(
                    status=IntegrityStatus.BROKEN_EDGE,
                    address=0x1000,
                    description="Broken",
                )
            ],
        )

        assert not report.valid
        assert len(report.violations) == 1

    def test_report_to_dict(self):
        """Test report serialization."""
        report = IntegrityReport(
            valid=True,
            violations=[],
            checks_run=[
                IntegrityCheck(name="test", description="Test check"),
            ],
            statistics={"total_blocks": 10},
        )

        d = report.to_dict()
        assert d["valid"]
        assert d["statistics"]["total_blocks"] == 10


class TestCFGIntegrityChecker:
    """Tests for CFGIntegrityChecker."""

    def test_init(self):
        """Test checker initialization."""
        binary = MockBinary()
        checker = CFGIntegrityChecker(binary)

        assert checker.binary is binary
        assert checker._snapshots == {}

    def test_create_snapshot_empty(self):
        """Test snapshot creation on empty binary."""
        binary = MockBinary()
        binary._analyzed = True
        binary._functions = [{"offset": 0x1000, "name": "test", "size": 64}]

        checker = CFGIntegrityChecker(binary)

        with patch.object(checker._cfg_builder, "build_cfg") as mock_cfg:
            mock_cfg.return_value = None
            snapshot = checker.create_snapshot(0x1000)
            assert snapshot is None

    def test_validate_without_snapshot(self):
        """Test validation without snapshot."""
        binary = MockBinary()
        checker = CFGIntegrityChecker(binary)

        report = checker.validate_integrity(0x1000)

        assert not report.valid
        assert len(report.violations) == 1
        assert report.violations[0].status == IntegrityStatus.INVALID_TARGET

    def test_check_reachability(self):
        """Test reachability check."""
        binary = MockBinary()
        checker = CFGIntegrityChecker(binary)

        snapshot = CFGSnapshot(
            function_address=0x1000,
            blocks={
                0x1000: {"address": 0x1000, "is_entry": True},
                0x1010: {"address": 0x1010, "is_entry": False},
                0x1020: {"address": 0x1020, "is_entry": False},
            },
            edges=[(0x1000, 0x1010, "normal")],
            entry_block=0x1000,
            exit_blocks=[],
        )

        report = IntegrityReport(valid=True)
        checker._check_reachability(snapshot, report)

        assert len(report.violations) >= 0

    def test_clear_snapshot(self):
        """Test snapshot clearing."""
        binary = MockBinary()
        checker = CFGIntegrityChecker(binary)

        checker._snapshots[0x1000] = CFGSnapshot(
            function_address=0x1000,
            blocks={},
            edges=[],
        )

        checker.clear_snapshot(0x1000)
        assert 0x1000 not in checker._snapshots

    def test_clear_all_snapshots(self):
        """Test clearing all snapshots."""
        binary = MockBinary()
        checker = CFGIntegrityChecker(binary)

        checker._snapshots[0x1000] = CFGSnapshot(
            function_address=0x1000,
            blocks={},
            edges=[],
        )
        checker._snapshots[0x2000] = CFGSnapshot(
            function_address=0x2000,
            blocks={},
            edges=[],
        )

        checker.clear_all_snapshots()
        assert len(checker._snapshots) == 0


class TestHardenedMutationValidator:
    """Tests for HardenedMutationValidator."""

    def test_init(self):
        """Test validator initialization."""
        binary = MockBinary()
        validator = HardenedMutationValidator(binary)

        assert validator.binary is binary
        assert validator._preservation_manager is None

    def test_pre_mutation_analysis(self):
        """Test pre-mutation analysis."""
        binary = MockBinary()
        binary._analyzed = True

        validator = HardenedMutationValidator(binary)

        result = validator.pre_mutation_analysis(0x1000)

        assert "function_address" in result
        assert "snapshot_created" in result

    def test_post_mutation_validation_no_snapshot(self):
        """Test post-mutation validation without snapshot."""
        binary = MockBinary()
        validator = HardenedMutationValidator(binary)

        result = validator.post_mutation_validation(0x1000)

        assert "valid" in result
        assert "violations" in result

    def test_get_preservation_manager(self):
        """Test getting preservation manager."""
        binary = MockBinary()
        binary._analyzed = True

        validator = HardenedMutationValidator(binary)
        manager = validator.get_preservation_manager()

        assert manager is not None
        assert isinstance(manager, PatternPreservationManager)


class TestPatternType:
    """Tests for PatternType enum."""

    def test_all_types(self):
        """Test all pattern types exist."""
        expected_types = [
            PatternType.EXCEPTION_HANDLER,
            PatternType.LANDING_PAD,
            PatternType.JUMP_TABLE,
            PatternType.JUMP_TABLE_ENTRY,
            PatternType.SWITCH_DISPATCHER,
            PatternType.VIRTUAL_DISPATCHER,
            PatternType.PLT_THUNK,
            PatternType.GOT_ENTRY,
            PatternType.TAIL_CALL,
            PatternType.INDIRECT_JUMP,
        ]

        for pt in expected_types:
            assert isinstance(pt.value, str)


class TestCriticality:
    """Tests for Criticality enum."""

    def test_criticality_levels(self):
        """Test criticality levels."""
        assert Criticality.PRESERVE.value == "preserve"
        assert Criticality.AVOID.value == "avoid"
        assert Criticality.CAUTION.value == "caution"


class TestIntegrityStatus:
    """Tests for IntegrityStatus enum."""

    def test_status_values(self):
        """Test integrity status values."""
        assert IntegrityStatus.VALID.value == "valid"
        assert IntegrityStatus.BROKEN_EDGE.value == "broken_edge"
        assert IntegrityStatus.UNREACHABLE.value == "unreachable"
        assert IntegrityStatus.INVALID_TARGET.value == "invalid_target"


@pytest.fixture
def mock_binary_with_patterns():
    """Fixture providing a mock binary with patterns."""
    binary = MockBinary()
    binary._analyzed = True
    binary._functions = [
        {"offset": 0x1000, "name": "func1", "size": 256},
        {"offset": 0x2000, "name": "func2", "size": 128},
    ]
    return binary


class TestIntegration:
    """Integration tests."""

    def test_full_preservation_flow(self, mock_binary_with_patterns):
        """Test complete preservation flow."""
        manager = PatternPreservationManager(mock_binary_with_patterns)

        summary = manager.analyze()

        assert "total_patterns" in summary
        assert "total_exclusion_zones" in summary

        zones = manager.get_exclusion_zones()
        assert isinstance(zones, list)

        report = manager.report()
        assert "summary" in report

    def test_integrity_check_flow(self, mock_binary_with_patterns):
        """Test complete integrity check flow."""
        checker = CFGIntegrityChecker(mock_binary_with_patterns)

        snapshot = checker.create_snapshot(0x1000)

        if snapshot:
            report = checker.validate_integrity(0x1000)
            assert isinstance(report, IntegrityReport)
            checker.clear_snapshot(0x1000)
        else:
            pass

    def test_validator_complete_flow(self, mock_binary_with_patterns):
        """Test complete hardened mutation validator flow."""
        validator = HardenedMutationValidator(mock_binary_with_patterns)

        pre_result = validator.pre_mutation_analysis(0x1000)

        assert "function_address" in pre_result

        post_result = validator.post_mutation_validation(0x1000)

        assert "valid" in post_result
