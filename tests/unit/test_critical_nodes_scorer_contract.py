from r2morph.analysis.critical_nodes_scorer import get_all_scores, get_safest_addresses, score_address
from tests.utils.assertions import expect

_EXPECTED_SCORE_ADDRESS_0X1000_CFG_CRITICAL_NODES_0_8 = 0.8


def test_critical_nodes_scorer_contract() -> None:
    class _Block:
        def __init__(self, block_type=None, predecessors=None):
            self.block_type = block_type
            self.predecessors = predecessors or []

    class _Cfg:
        def __init__(self):
            self.blocks = {0x1000: _Block(), 0x1010: _Block()}

        def get_block(self, address):
            return self.blocks.get(address)

    cfg = _Cfg()
    critical_nodes: dict[int, object] = {}

    expect(score_address(4096, cfg, critical_nodes) == _EXPECTED_SCORE_ADDRESS_0X1000_CFG_CRITICAL_NODES_0_8)
    expect(get_safest_addresses(cfg, count=1, critical_nodes=critical_nodes))
    expect(get_all_scores(cfg, critical_nodes))
