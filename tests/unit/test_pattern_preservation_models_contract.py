"""Contract tests for pattern preservation models."""

from __future__ import annotations

from r2morph.analysis.pattern_preservation_models import (
    Criticality,
    ExclusionZone,
    PatternType,
    PreservedPattern,
)
from tests.utils.assertions import expect

_EXPECTED_PATTERN_SIZE_16 = 0x10
_EXPECTED_ZONE_EXPANDED_START_4092 = 0x0FFC


def test_pattern_type_values() -> None:
    expect(PatternType.EXCEPTION_HANDLER.value == "exception_handler")
    expect(PatternType.PLT_THUNK.value == "plt_thunk")


def test_preserved_pattern_serialization() -> None:
    pattern = PreservedPattern(
        type=PatternType.JUMP_TABLE,
        start_address=0x1000,
        end_address=0x1010,
        criticality=Criticality.CAUTION,
        source="test",
    )

    expect(pattern.size == _EXPECTED_PATTERN_SIZE_16)
    expect(pattern.to_dict()["criticality"] == "caution")


def test_exclusion_zone_expansion() -> None:
    zone = ExclusionZone(
        start_address=0x1000,
        end_address=0x1010,
        pattern_type=PatternType.PLT_THUNK,
        radius=4,
    )

    expect(zone.expanded_start == _EXPECTED_ZONE_EXPANDED_START_4092)
    expect(zone.contains(0x1002))
