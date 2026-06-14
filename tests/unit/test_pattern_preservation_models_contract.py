"""Contract tests for pattern preservation models."""

from __future__ import annotations

from r2morph.analysis.pattern_preservation_models import (
    Criticality,
    ExclusionZone,
    PatternType,
    PreservedPattern,
)


def test_pattern_type_values() -> None:
    assert PatternType.EXCEPTION_HANDLER.value == "exception_handler"
    assert PatternType.PLT_THUNK.value == "plt_thunk"


def test_preserved_pattern_serialization() -> None:
    pattern = PreservedPattern(
        type=PatternType.JUMP_TABLE,
        start_address=0x1000,
        end_address=0x1010,
        criticality=Criticality.CAUTION,
        source="test",
    )

    assert pattern.size == 0x10
    assert pattern.to_dict()["criticality"] == "caution"


def test_exclusion_zone_expansion() -> None:
    zone = ExclusionZone(
        start_address=0x1000,
        end_address=0x1010,
        pattern_type=PatternType.PLT_THUNK,
        radius=4,
    )

    assert zone.expanded_start == 0x0FFC
    assert zone.contains(0x1002)
