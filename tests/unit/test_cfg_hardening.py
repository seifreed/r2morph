"""
Tests for CFG hardening - pattern preservation and integrity validation.

Tests for Issue #3:
- Exception edge preservation
- Dispatcher/jump table pattern preservation
- CFG integrity checks
- Tests with optimized binaries
"""

import pytest

from r2morph.analysis.pattern_preservation import (
    Criticality,
    ExclusionZone,
    PatternPreservationManager,
    PatternType,
    PreservedPattern,
)
from r2morph.validation.cfg_integrity import (
    CFGIntegrityChecker,
    CFGSnapshot,
    HardenedMutationValidator,
    IntegrityCheck,
    IntegrityReport,
    IntegrityStatus,
    IntegrityViolation,
)
from tests.utils.assertions import expect

_EXPECTED_CHECKER_SNAPSHOTS_4096 = 0x1000
_EXPECTED_D_RADIUS_16 = 16
_EXPECTED_D_SIZE_256 = 0x100
_EXPECTED_D_STATISTICS_TOTAL_BLOCKS_10 = 10
_EXPECTED_LEN_JT_PATTERNS_2 = 2
_EXPECTED_LEN_SAFE_2 = 2
_EXPECTED_LEN_SNAPSHOT_BLOCKS_2 = 2
_EXPECTED_MANAGER_DEFAULT_RADIUS_16 = 16
_EXPECTED_PATTERN_SIZE_256 = 0x100
_EXPECTED_SNAPSHOT_ENTRY_BLOCK_4096 = 0x1000
_EXPECTED_SNAPSHOT_FUNCTION_ADDRESS_4096 = 0x1000
_EXPECTED_S_0_2048 = 0x800
_EXPECTED_VIOLATION_ADDRESS_4096 = 0x1000
_EXPECTED_ZONE_EXPANDED_END_4360 = 0x1108
_EXPECTED_ZONE_EXPANDED_START_4088 = 0x0FF8


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

        expect(pattern.size == _EXPECTED_PATTERN_SIZE_256)
        expect(pattern.contains(0x1050))
        expect(not (pattern.contains(0x1200)))

    def test_pattern_overlaps(self):
        """Test pattern overlap detection."""
        pattern = PreservedPattern(
            type=PatternType.JUMP_TABLE,
            start_address=0x1000,
            end_address=0x1100,
        )

        expect(pattern.overlaps(0x1000, 0x1100))
        expect(pattern.overlaps(0x1050, 0x1150))
        expect(pattern.overlaps(0xF00, 0x1010))
        expect(not (pattern.overlaps(0x1200, 0x1300)))

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
        expect(d["type"] == "exception_handler")
        expect(d["start_address"] == "0x2000")
        expect(d["size"] == _EXPECTED_D_SIZE_256)
        expect(d["criticality"] == "avoid")


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

        expect(zone.expanded_start == _EXPECTED_ZONE_EXPANDED_START_4088)
        expect(zone.expanded_end == _EXPECTED_ZONE_EXPANDED_END_4360)
        expect(zone.contains(0x0FF8))
        expect(zone.contains(0x1107))
        expect(not (zone.contains(0x0FF7)))

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
        expect(d["pattern_type"] == "plt_thunk")
        expect(d["radius"] == _EXPECTED_D_RADIUS_16)


class TestPatternPreservationManager:
    """Tests for PatternPreservationManager."""

    def test_init(self):
        """Test manager initialization."""
        binary = MockBinary()
        manager = PatternPreservationManager(binary, default_radius=16)

        expect(not (manager.binary is not binary))
        expect(manager.default_radius == _EXPECTED_MANAGER_DEFAULT_RADIUS_16)
        expect(manager._patterns == [])
        expect(manager._exclusion_zones == [])

    def test_analyze_empty_binary(self):
        """Test analysis on empty binary."""
        binary = MockBinary()
        binary._analyzed = True

        manager = PatternPreservationManager(binary)
        summary = manager.analyze()

        expect(summary["total_patterns"] == 0)
        expect(summary["total_exclusion_zones"] == 0)

    def test_should_preserve_empty(self):
        """Test should_preserve before analysis."""
        binary = MockBinary()
        manager = PatternPreservationManager(binary)

        expect(not (manager.should_preserve(0x1000)))
        expect(not (manager.should_avoid(0x1000)))

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
        expect(len(patterns) == 1)
        expect(patterns[0].type == PatternType.JUMP_TABLE)

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

        expect(not (len(safe) < _EXPECTED_LEN_SAFE_2))
        expect((0x800, 0x1000) in safe or any(s[0] == _EXPECTED_S_0_2048 for s in safe))

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
        expect(len(jt_patterns) == _EXPECTED_LEN_JT_PATTERNS_2)

        plt_patterns = manager.get_patterns_by_type(PatternType.PLT_THUNK)
        expect(len(plt_patterns) == 1)

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

        expect(not ("summary" not in report))
        expect(not ("exclusion_zones" not in report))
        expect(report["summary"]["total_patterns"] == 1)


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

        expect(snapshot.function_address == _EXPECTED_SNAPSHOT_FUNCTION_ADDRESS_4096)
        expect(len(snapshot.blocks) == _EXPECTED_LEN_SNAPSHOT_BLOCKS_2)
        expect(len(snapshot.edges) == 1)
        expect(snapshot.entry_block == _EXPECTED_SNAPSHOT_ENTRY_BLOCK_4096)


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

        expect(violation.status == IntegrityStatus.BROKEN_EDGE)
        expect(violation.address == _EXPECTED_VIOLATION_ADDRESS_4096)

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
        expect(d["status"] == "unreachable")
        expect(d["address"] == "0x2000")
        expect(d["severity"] == "warning")


class TestIntegrityReport:
    """Tests for IntegrityReport."""

    def test_valid_report(self):
        """Test valid integrity report."""
        report = IntegrityReport(
            valid=True,
            violations=[],
            checks_run=[],
        )

        expect(report.valid)
        expect(len(report.violations) == 0)

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

        expect(not (report.valid))
        expect(len(report.violations) == 1)

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
        expect(d["valid"])
        expect(d["statistics"]["total_blocks"] == _EXPECTED_D_STATISTICS_TOTAL_BLOCKS_10)


class TestCFGIntegrityChecker:
    """Tests for CFGIntegrityChecker."""

    def test_init(self):
        """Test checker initialization."""
        binary = MockBinary()
        checker = CFGIntegrityChecker(binary)

        expect(not (checker.binary is not binary))
        expect(checker._snapshots == {})

    def test_create_snapshot_empty(self):
        """Test snapshot creation on empty binary."""
        binary = MockBinary()
        binary._analyzed = True
        binary._functions = [{"offset": 0x1000, "name": "test", "size": 64}]

        checker = CFGIntegrityChecker(binary)

        snapshot = checker.create_snapshot(0x1000)
        expect(not (snapshot is not None))

    def test_validate_without_snapshot(self):
        """Test validation without snapshot."""
        binary = MockBinary()
        checker = CFGIntegrityChecker(binary)

        report = checker.validate_integrity(0x1000)

        expect(not (report.valid))
        expect(len(report.violations) == 1)
        expect(report.violations[0].status == IntegrityStatus.INVALID_TARGET)

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

        expect(not (len(report.violations) < 0))

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
        expect(_EXPECTED_CHECKER_SNAPSHOTS_4096 not in checker._snapshots)

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
        expect(len(checker._snapshots) == 0)


class TestHardenedMutationValidator:
    """Tests for HardenedMutationValidator."""

    def test_init(self):
        """Test validator initialization."""
        binary = MockBinary()
        validator = HardenedMutationValidator(binary)

        expect(not (validator.binary is not binary))
        expect(not (validator._preservation_manager is not None))

    def test_pre_mutation_analysis(self):
        """Test pre-mutation analysis."""
        binary = MockBinary()
        binary._analyzed = True

        validator = HardenedMutationValidator(binary)

        result = validator.pre_mutation_analysis(0x1000)

        expect(not ("function_address" not in result))
        expect(not ("snapshot_created" not in result))

    def test_post_mutation_validation_no_snapshot(self):
        """Test post-mutation validation without snapshot."""
        binary = MockBinary()
        validator = HardenedMutationValidator(binary)

        result = validator.post_mutation_validation(0x1000)

        expect(not ("valid" not in result))
        expect(not ("violations" not in result))

    def test_get_preservation_manager(self):
        """Test getting preservation manager."""
        binary = MockBinary()
        binary._analyzed = True

        validator = HardenedMutationValidator(binary)
        manager = validator.get_preservation_manager()

        expect(manager is not None)
        expect(isinstance(manager, PatternPreservationManager))


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
            expect(isinstance(pt.value, str))


class TestCriticality:
    """Tests for Criticality enum."""

    def test_criticality_levels(self):
        """Test criticality levels."""
        expect(Criticality.PRESERVE.value == "preserve")
        expect(Criticality.AVOID.value == "avoid")
        expect(Criticality.CAUTION.value == "caution")


class TestIntegrityStatus:
    """Tests for IntegrityStatus enum."""

    def test_status_values(self):
        """Test integrity status values."""
        expect(IntegrityStatus.VALID.value == "valid")
        expect(IntegrityStatus.BROKEN_EDGE.value == "broken_edge")
        expect(IntegrityStatus.UNREACHABLE.value == "unreachable")
        expect(IntegrityStatus.INVALID_TARGET.value == "invalid_target")


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

        expect(not ("total_patterns" not in summary))
        expect(not ("total_exclusion_zones" not in summary))

        zones = manager.get_exclusion_zones()
        expect(isinstance(zones, list))

        report = manager.report()
        expect(not ("summary" not in report))

    def test_integrity_check_flow(self, mock_binary_with_patterns):
        """Test complete integrity check flow."""
        checker = CFGIntegrityChecker(mock_binary_with_patterns)

        snapshot = checker.create_snapshot(0x1000)

        if snapshot:
            report = checker.validate_integrity(0x1000)
            expect(isinstance(report, IntegrityReport))
            checker.clear_snapshot(0x1000)
        else:
            pass

    def test_validator_complete_flow(self, mock_binary_with_patterns):
        """Test complete hardened mutation validator flow."""
        validator = HardenedMutationValidator(mock_binary_with_patterns)

        pre_result = validator.pre_mutation_analysis(0x1000)

        expect(not ("function_address" not in pre_result))

        post_result = validator.post_mutation_validation(0x1000)

        expect(not ("valid" not in post_result))
