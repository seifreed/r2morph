from r2morph.analysis.memory_flow_models import MemoryAccess, MemoryAccessType, MemoryDependency, MemoryLocation
from tests.utils.assertions import expect


def test_memory_flow_models_contract() -> None:
    loc = MemoryLocation(address=0x1000, size=8, name="buf", location_type="stack")
    expect(loc.to_dict()["address"] == "0x1000")
    expect(loc.overlaps(MemoryLocation(address=0x1004, size=4)))

    access = MemoryAccess(address=0x200, location=loc, access_type=MemoryAccessType.WRITE)
    expect(access.to_dict()["access_type"] == "write")

    dep = MemoryDependency(source=access, target=access, dependency_type="flow")
    expect(dep.to_dict()["type"] == "flow")
