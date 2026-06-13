from r2morph.mutations.conflict_models import (
    Conflict,
    ConflictSeverity,
    ConflictType,
    MutationRegion,
    Resolution,
)


def test_mutation_region_conflict_types_stay_stable() -> None:
    region1 = MutationRegion(start=0x1000, end=0x1100, affected_registers={"eax"})
    region2 = MutationRegion(start=0x1200, end=0x1300, affected_registers={"rax"})

    assert region1.conflicts_with(region2) == ConflictType.REGISTER_INTERFERENCE
    assert region1.to_dict()["start"] == "0x1000"


def test_conflict_and_resolution_serialization_stay_stable() -> None:
    region1 = MutationRegion(start=0x1000, end=0x1100)
    region2 = MutationRegion(start=0x1200, end=0x1300)
    conflict = Conflict(
        conflict_id=7,
        conflict_type=ConflictType.OVERLAP,
        severity=ConflictSeverity.HIGH,
        region1=region1,
        region2=region2,
        description="demo",
        resolution_hint="hint",
    )
    resolution = Resolution(conflict=conflict, strategy="skip", action="skip_second")

    assert conflict.to_dict()["conflict_id"] == 7
    assert resolution.to_dict()["strategy"] == "skip"
