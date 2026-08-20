from r2morph.analysis.critical_nodes_models import AddressRange, CriticalNode
from tests.utils.assertions import expect

_EXPECTED_MERGED_END_4144 = 0x1030
_EXPECTED_MERGED_START_4096 = 0x1000
_EXPECTED_R_4112 = 0x1010
_EXPECTED_R_SIZE_33 = 0x21


def test_critical_nodes_models_contract() -> None:
    r = AddressRange(start=0x1000, end=0x1020)
    expect(not (_EXPECTED_R_4112 not in r))
    expect(r.size() == _EXPECTED_R_SIZE_33)
    merged = r.merge(AddressRange(start=0x1018, end=0x1030))
    expect(merged.start == _EXPECTED_MERGED_START_4096)
    expect(merged.end == _EXPECTED_MERGED_END_4144)

    node = CriticalNode(
        address=0x2000,
        node_type="branch_target",
        reason="target of a branch",
        exclusion_radius=4,
    )
    data = node.to_dict()
    expect(data["address"] == "0x2000")
    expect(data["type"] == "branch_target")
