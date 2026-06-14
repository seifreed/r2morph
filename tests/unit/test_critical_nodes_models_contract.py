from r2morph.analysis.critical_nodes_models import AddressRange, CriticalNode


def test_critical_nodes_models_contract() -> None:
    r = AddressRange(start=0x1000, end=0x1020)
    assert 0x1010 in r
    assert r.size() == 0x21
    merged = r.merge(AddressRange(start=0x1018, end=0x1030))
    assert merged.start == 0x1000
    assert merged.end == 0x1030

    node = CriticalNode(
        address=0x2000,
        node_type="branch_target",
        reason="target of a branch",
        exclusion_radius=4,
    )
    data = node.to_dict()
    assert data["address"] == "0x2000"
    assert data["type"] == "branch_target"
