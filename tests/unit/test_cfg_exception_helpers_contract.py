from types import SimpleNamespace

from r2morph.analysis.cfg_exception_helpers import detect_exception_edges
from r2morph.analysis.cfg_models import BasicBlock, ControlFlowGraph
from tests.utils.assertions import expect


class _Binary:
    def __init__(self) -> None:
        self.r2 = SimpleNamespace(cmdj=lambda _cmd: [{"addr": 0x1000, "landing_pads": [0x1010]}])

    def get_arch_info(self) -> dict[str, str]:
        return {"format": "ELF"}


def test_cfg_exception_helpers_contract() -> None:
    binary = _Binary()
    cfg = ControlFlowGraph(function_address=0x1000, function_name="main")
    cfg.add_block(BasicBlock(address=0x1010, size=4))

    edges = detect_exception_edges(binary, cfg, 0x1000)

    expect(edges == [])
    expect(cfg.get_block(4112).block_type.value == "landing_pad")
    expect(not (cfg.get_block(0x1010).metadata["is_landing_pad"] is not True))
