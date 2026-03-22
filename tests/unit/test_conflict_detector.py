"""
Tests for conflict detection module.
"""

import pytest

from r2morph.mutations.conflict_detector import (
    Conflict,
    ConflictDetector,
    ConflictSeverity,
    ConflictType,
    MutationRegion,
    RegionTracker,
    Resolution,
    analyze_mutations_for_conflicts,
)


class TestMutationRegion:
    """Tests for MutationRegion dataclass."""

    def test_region_creation(self):
        """Test creating a mutation region."""
        region = MutationRegion(
            start=0x1000,
            end=0x1100,
            pass_name="test_pass",
            affected_registers={"eax", "ebx"},
            affected_memory={0x2000},
        )
        assert region.start == 0x1000
        assert region.end == 0x1100
        assert region.pass_name == "test_pass"
        assert "eax" in region.affected_registers
        assert 0x2000 in region.affected_memory

    def test_region_defaults(self):
        """Test default values for region."""
        region = MutationRegion(start=0x1000, end=0x1100)
        assert region.pass_name == ""
        assert region.affected_registers == set()
        assert region.affected_memory == set()
        assert region.control_flow_changed is False
        assert region.metadata == {}

    def test_region_hash(self):
        """Test region hashing."""
        region1 = MutationRegion(start=0x1000, end=0x1100, pass_name="pass1")
        region2 = MutationRegion(start=0x1000, end=0x1100, pass_name="pass1")
        region3 = MutationRegion(start=0x1000, end=0x1100, pass_name="pass2")

        assert hash(region1) == hash(region2)
        assert hash(region1) != hash(region3)

    def test_overlaps_true(self):
        """Test overlap detection when regions overlap."""
        region1 = MutationRegion(start=0x1000, end=0x1100)
        region2 = MutationRegion(start=0x1050, end=0x1150)

        assert region1.overlaps(region2) is True
        assert region2.overlaps(region1) is True

    def test_overlaps_false(self):
        """Test overlap detection when regions don't overlap."""
        region1 = MutationRegion(start=0x1000, end=0x1100)
        region2 = MutationRegion(start=0x1100, end=0x1200)

        assert region1.overlaps(region2) is False
        assert region2.overlaps(region1) is False

    def test_overlaps_adjacent(self):
        """Test overlap detection for adjacent regions."""
        region1 = MutationRegion(start=0x1000, end=0x1100)
        region2 = MutationRegion(start=0x1100, end=0x1200)

        assert region1.overlaps(region2) is False

    def test_conflicts_with_overlap(self):
        """Test conflict detection for overlapping regions."""
        region1 = MutationRegion(start=0x1000, end=0x1100, pass_name="pass1")
        region2 = MutationRegion(start=0x1050, end=0x1150, pass_name="pass2")

        conflict = region1.conflicts_with(region2)
        assert conflict == ConflictType.OVERLAP

    def test_conflicts_with_register_interference(self):
        """Test conflict detection for register interference."""
        region1 = MutationRegion(
            start=0x1000,
            end=0x1100,
            affected_registers={"eax", "ebx"},
        )
        region2 = MutationRegion(
            start=0x2000,
            end=0x2100,
            affected_registers={"ebx", "ecx"},
        )

        conflict = region1.conflicts_with(region2)
        assert conflict == ConflictType.REGISTER_INTERFERENCE

    def test_conflicts_with_memory_interference(self):
        """Test conflict detection for memory interference."""
        region1 = MutationRegion(
            start=0x1000,
            end=0x1100,
            affected_memory={0x5000, 0x5008},
        )
        region2 = MutationRegion(
            start=0x2000,
            end=0x2100,
            affected_memory={0x5008, 0x5010},
        )

        conflict = region1.conflicts_with(region2)
        assert conflict == ConflictType.MEMORY_INTERFERENCE

    def test_conflicts_with_control_flow(self):
        """Test conflict detection for control flow changes."""
        region1 = MutationRegion(
            start=0x1000,
            end=0x1100,
            control_flow_changed=True,
        )
        region2 = MutationRegion(
            start=0x2000,
            end=0x2100,
            control_flow_changed=True,
        )

        conflict = region1.conflicts_with(region2)
        assert conflict == ConflictType.CONTROL_FLOW

    def test_conflicts_with_no_conflict(self):
        """Test conflict detection for non-conflicting regions."""
        region1 = MutationRegion(
            start=0x1000,
            end=0x1100,
            affected_registers={"eax"},
        )
        region2 = MutationRegion(
            start=0x2000,
            end=0x2100,
            affected_registers={"ebx"},
        )

        conflict = region1.conflicts_with(region2)
        assert conflict is None

    def test_to_dict(self):
        """Test region serialization."""
        region = MutationRegion(
            start=0x1000,
            end=0x1100,
            pass_name="test_pass",
            affected_registers={"eax", "ebx"},
            affected_memory={0x2000, 0x2008},
            control_flow_changed=True,
        )

        result = region.to_dict()
        assert result["start"] == "0x1000"
        assert result["end"] == "0x1100"
        assert result["pass_name"] == "test_pass"
        assert sorted(result["affected_registers"]) == ["eax", "ebx"]
        assert result["control_flow_changed"] is True


class TestConflict:
    """Tests for Conflict dataclass."""

    def test_conflict_creation(self):
        """Test creating a conflict."""
        region1 = MutationRegion(start=0x1000, end=0x1100)
        region2 = MutationRegion(start=0x1050, end=0x1150)

        conflict = Conflict(
            conflict_id=1,
            conflict_type=ConflictType.OVERLAP,
            severity=ConflictSeverity.HIGH,
            region1=region1,
            region2=region2,
            description="Test conflict",
            resolution_hint="Test hint",
        )

        assert conflict.conflict_id == 1
        assert conflict.conflict_type == ConflictType.OVERLAP
        assert conflict.severity == ConflictSeverity.HIGH
        assert conflict.description == "Test conflict"

    def test_conflict_to_dict(self):
        """Test conflict serialization."""
        region1 = MutationRegion(start=0x1000, end=0x1100, pass_name="pass1")
        region2 = MutationRegion(start=0x1050, end=0x1150, pass_name="pass2")

        conflict = Conflict(
            conflict_id=1,
            conflict_type=ConflictType.OVERLAP,
            severity=ConflictSeverity.HIGH,
            region1=region1,
            region2=region2,
            description="Test conflict",
        )

        result = conflict.to_dict()
        assert result["conflict_id"] == 1
        assert result["type"] == "overlap"
        assert result["severity"] == "high"
        assert result["description"] == "Test conflict"
        assert "region1" in result
        assert "region2" in result


class TestResolution:
    """Tests for Resolution dataclass."""

    def test_resolution_creation(self):
        """Test creating a resolution."""
        region1 = MutationRegion(start=0x1000, end=0x1100)
        region2 = MutationRegion(start=0x1050, end=0x1150)
        conflict = Conflict(
            conflict_id=1,
            conflict_type=ConflictType.OVERLAP,
            severity=ConflictSeverity.HIGH,
            region1=region1,
            region2=region2,
        )

        resolution = Resolution(
            conflict=conflict,
            strategy="reorder",
            description="Test resolution",
            action="apply_sequential",
        )

        assert resolution.conflict == conflict
        assert resolution.strategy == "reorder"
        assert resolution.description == "Test resolution"

    def test_resolution_to_dict(self):
        """Test resolution serialization."""
        region1 = MutationRegion(start=0x1000, end=0x1100)
        region2 = MutationRegion(start=0x1050, end=0x1150)
        conflict = Conflict(
            conflict_id=1,
            conflict_type=ConflictType.OVERLAP,
            severity=ConflictSeverity.HIGH,
            region1=region1,
            region2=region2,
        )

        resolution = Resolution(
            conflict=conflict,
            strategy="reorder",
            description="Test resolution",
            action="apply_sequential",
        )

        result = resolution.to_dict()
        assert result["conflict_id"] == 1
        assert result["strategy"] == "reorder"
        assert result["description"] == "Test resolution"
        assert result["action"] == "apply_sequential"


class TestRegionTracker:
    """Tests for RegionTracker class."""

    def test_track_mutation(self):
        """Test tracking a mutation."""
        tracker = RegionTracker()
        region_id = tracker.track_mutation(
            start=0x1000,
            end=0x1100,
            pass_name="test_pass",
            affected_registers={"eax"},
        )

        assert region_id == 0
        assert tracker.get_region_count() == 1

    def test_track_multiple_mutations(self):
        """Test tracking multiple mutations."""
        tracker = RegionTracker()

        region_id1 = tracker.track_mutation(start=0x1000, end=0x1100, pass_name="pass1")
        region_id2 = tracker.track_mutation(start=0x2000, end=0x2100, pass_name="pass2")

        assert region_id1 == 0
        assert region_id2 == 1
        assert tracker.get_region_count() == 2

    def test_get_regions_at(self):
        """Test getting regions at an address."""
        tracker = RegionTracker()
        tracker.track_mutation(start=0x1000, end=0x1100, pass_name="test_pass")

        regions = tracker.get_regions_at(0x1050)
        assert len(regions) == 1
        assert regions[0].pass_name == "test_pass"

    def test_get_regions_at_no_match(self):
        """Test getting regions when no match."""
        tracker = RegionTracker()
        tracker.track_mutation(start=0x1000, end=0x1100, pass_name="test_pass")

        regions = tracker.get_regions_at(0x2000)
        assert len(regions) == 0

    def test_get_overlaps(self):
        """Test finding overlapping regions."""
        tracker = RegionTracker()
        tracker.track_mutation(start=0x1000, end=0x1100, pass_name="pass1")
        tracker.track_mutation(start=0x1050, end=0x1150, pass_name="pass2")
        tracker.track_mutation(start=0x2000, end=0x2100, pass_name="pass3")

        overlaps = tracker.get_overlaps()
        assert len(overlaps) == 1
        assert overlaps[0][0].pass_name == "pass1"
        assert overlaps[0][1].pass_name == "pass2"

    def test_get_overlaps_none(self):
        """Test finding no overlapping regions."""
        tracker = RegionTracker()
        tracker.track_mutation(start=0x1000, end=0x1100, pass_name="pass1")
        tracker.track_mutation(start=0x2000, end=0x2100, pass_name="pass2")

        overlaps = tracker.get_overlaps()
        assert len(overlaps) == 0

    def test_clear(self):
        """Test clearing tracked regions."""
        tracker = RegionTracker()
        tracker.track_mutation(start=0x1000, end=0x1100, pass_name="test_pass")

        tracker.clear()
        assert tracker.get_region_count() == 0


class TestConflictDetector:
    """Tests for ConflictDetector class."""

    def test_detect_overlaps(self):
        """Test detecting overlapping regions."""
        detector = ConflictDetector()
        region1 = MutationRegion(start=0x1000, end=0x1100, pass_name="pass1")
        region2 = MutationRegion(start=0x1050, end=0x1150, pass_name="pass2")

        conflicts = detector.detect_overlaps([region1, region2])
        assert len(conflicts) == 1
        assert conflicts[0].conflict_type == ConflictType.OVERLAP
        assert conflicts[0].severity == ConflictSeverity.HIGH

    def test_detect_overlaps_none(self):
        """Test detecting no overlaps."""
        detector = ConflictDetector()
        region1 = MutationRegion(start=0x1000, end=0x1100, pass_name="pass1")
        region2 = MutationRegion(start=0x2000, end=0x2100, pass_name="pass2")

        conflicts = detector.detect_overlaps([region1, region2])
        assert len(conflicts) == 0

    def test_find_interferences_register(self):
        """Test finding register interferences."""
        detector = ConflictDetector()
        region1 = MutationRegion(
            start=0x1000,
            end=0x1100,
            affected_registers={"eax", "ebx"},
        )
        region2 = MutationRegion(
            start=0x2000,
            end=0x2100,
            affected_registers={"ebx", "ecx"},
        )

        conflicts = detector.find_interferences([region1, region2])
        assert len(conflicts) == 1
        assert conflicts[0].conflict_type == ConflictType.REGISTER_INTERFERENCE

    def test_find_interferences_memory(self):
        """Test finding memory interferences."""
        detector = ConflictDetector()
        region1 = MutationRegion(
            start=0x1000,
            end=0x1100,
            affected_memory={0x5000},
        )
        region2 = MutationRegion(
            start=0x2000,
            end=0x2100,
            affected_memory={0x5000},
        )

        conflicts = detector.find_interferences([region1, region2])
        assert len(conflicts) == 1
        assert conflicts[0].conflict_type == ConflictType.MEMORY_INTERFERENCE

    def test_find_interferences_control_flow(self):
        """Test finding control flow conflicts."""
        detector = ConflictDetector()
        region1 = MutationRegion(
            start=0x1000,
            end=0x1100,
            control_flow_changed=True,
        )
        region2 = MutationRegion(
            start=0x2000,
            end=0x2100,
            control_flow_changed=True,
        )

        conflicts = detector.find_interferences([region1, region2])
        assert len(conflicts) == 1
        assert conflicts[0].conflict_type == ConflictType.CONTROL_FLOW
        assert conflicts[0].severity == ConflictSeverity.CRITICAL

    def test_validate_pipeline(self):
        """Test validating a pipeline."""
        detector = ConflictDetector()
        region1 = MutationRegion(start=0x1000, end=0x1100, pass_name="pass1")
        region2 = MutationRegion(start=0x1050, end=0x1150, pass_name="pass2")

        conflicts = detector.validate_pipeline(
            [
                ("pass1", region1),
                ("pass2", region2),
            ]
        )
        assert len(conflicts) >= 1

    def test_suggest_resolutions_overlap(self):
        """Test suggesting resolution for overlap."""
        detector = ConflictDetector()
        region1 = MutationRegion(start=0x1000, end=0x1100)
        region2 = MutationRegion(start=0x1050, end=0x1150)
        conflict = Conflict(
            conflict_id=1,
            conflict_type=ConflictType.OVERLAP,
            severity=ConflictSeverity.HIGH,
            region1=region1,
            region2=region2,
        )

        resolutions = detector.suggest_resolutions([conflict])
        assert len(resolutions) == 1
        assert resolutions[0].strategy == "reorder"

    def test_suggest_resolutions_register(self):
        """Test suggesting resolution for register interference."""
        detector = ConflictDetector()
        region1 = MutationRegion(start=0x1000, end=0x1100)
        region2 = MutationRegion(start=0x2000, end=0x2100)
        conflict = Conflict(
            conflict_id=1,
            conflict_type=ConflictType.REGISTER_INTERFERENCE,
            severity=ConflictSeverity.MEDIUM,
            region1=region1,
            region2=region2,
        )

        resolutions = detector.suggest_resolutions([conflict])
        assert len(resolutions) == 1
        assert resolutions[0].strategy == "skip"

    def test_suggest_resolutions_control_flow(self):
        """Test suggesting resolution for control flow conflict."""
        detector = ConflictDetector()
        region1 = MutationRegion(start=0x1000, end=0x1100)
        region2 = MutationRegion(start=0x2000, end=0x2100)
        conflict = Conflict(
            conflict_id=1,
            conflict_type=ConflictType.CONTROL_FLOW,
            severity=ConflictSeverity.CRITICAL,
            region1=region1,
            region2=region2,
        )

        resolutions = detector.suggest_resolutions([conflict])
        assert len(resolutions) == 1
        assert resolutions[0].strategy == "abort"

    def test_get_region_tracker(self):
        """Test getting region tracker."""
        detector = ConflictDetector()
        tracker = detector.get_region_tracker()
        assert isinstance(tracker, RegionTracker)


class TestAnalyzeMutationsForConflicts:
    """Tests for the convenience function."""

    def test_analyze_no_mutations(self):
        """Test analyzing empty mutation list."""
        result = analyze_mutations_for_conflicts([])
        assert result["total_mutations"] == 0
        assert result["conflicts_found"] == 0
        assert result["has_critical"] is False

    def test_analyze_single_mutation(self):
        """Test analyzing single mutation."""
        result = analyze_mutations_for_conflicts([{"start": 0x1000, "size": 0x100, "pass_name": "test"}])
        assert result["total_mutations"] == 1
        assert result["conflicts_found"] == 0

    def test_analyze_conflicting_mutations(self):
        """Test analyzing conflicting mutations."""
        result = analyze_mutations_for_conflicts(
            [
                {"start": 0x1000, "size": 0x100, "pass_name": "pass1"},
                {"start": 0x1050, "size": 0x100, "pass_name": "pass2"},
            ]
        )
        assert result["total_mutations"] == 2
        assert result["conflicts_found"] >= 1
        assert result["has_high"] is True

    def test_analyze_with_registers(self):
        """Test analyzing mutations with register conflicts."""
        result = analyze_mutations_for_conflicts(
            [
                {
                    "start": 0x1000,
                    "size": 0x100,
                    "pass_name": "pass1",
                    "registers": ["eax", "ebx"],
                },
                {
                    "start": 0x2000,
                    "size": 0x100,
                    "pass_name": "pass2",
                    "registers": ["ebx", "ecx"],
                },
            ]
        )
        assert result["total_mutations"] == 2

        conflict_types = [c["type"] for c in result["conflicts"]]
        assert "register_interference" in conflict_types

    def test_analyze_with_control_flow(self):
        """Test analyzing mutations with control flow conflicts."""
        result = analyze_mutations_for_conflicts(
            [
                {
                    "start": 0x1000,
                    "size": 0x100,
                    "pass_name": "pass1",
                    "control_flow": True,
                },
                {
                    "start": 0x2000,
                    "size": 0x100,
                    "pass_name": "pass2",
                    "control_flow": True,
                },
            ]
        )
        assert result["has_critical"] is True

    def test_analyze_with_alternative_keys(self):
        """Test analyzing mutations with alternative key names."""
        result = analyze_mutations_for_conflicts(
            [
                {"address": 0x1000, "length": 0x100, "pass_name": "pass1"},
            ]
        )
        assert result["total_mutations"] == 1


class TestConflictSeverity:
    """Tests for conflict severity determination."""

    def test_severity_overlap(self):
        """Test severity for overlap conflicts."""
        detector = ConflictDetector()
        assert detector._determine_severity(ConflictType.OVERLAP) == ConflictSeverity.HIGH

    def test_severity_register(self):
        """Test severity for register interference."""
        detector = ConflictDetector()
        assert detector._determine_severity(ConflictType.REGISTER_INTERFERENCE) == ConflictSeverity.MEDIUM

    def test_severity_control_flow(self):
        """Test severity for control flow conflicts."""
        detector = ConflictDetector()
        assert detector._determine_severity(ConflictType.CONTROL_FLOW) == ConflictSeverity.CRITICAL

    def test_severity_dependency(self):
        """Test severity for dependency conflicts."""
        detector = ConflictDetector()
        assert detector._determine_severity(ConflictType.DEPENDENCY) == ConflictSeverity.LOW
