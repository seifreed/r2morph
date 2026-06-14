from r2morph.analysis.memory_flow_models import MemoryAccess, MemoryAccessType, MemoryDependency, MemoryLocation


def test_memory_flow_models_contract() -> None:
    loc = MemoryLocation(address=0x1000, size=8, name="buf", location_type="stack")
    assert loc.to_dict()["address"] == "0x1000"
    assert loc.overlaps(MemoryLocation(address=0x1004, size=4))

    access = MemoryAccess(address=0x200, location=loc, access_type=MemoryAccessType.WRITE)
    assert access.to_dict()["access_type"] == "write"

    dep = MemoryDependency(source=access, target=access, dependency_type="flow")
    assert dep.to_dict()["type"] == "flow"
