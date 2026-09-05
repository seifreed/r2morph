from r2morph.analysis.cfg_exception_helpers import detect_exception_edges
from r2morph.analysis.cfg_models import BasicBlock, ControlFlowGraph
from tests.unit.test_exception_reader_contract import _InMemoryElfExceptionBinary
from tests.utils.assertions import expect

_FUNCTION_ADDRESS = 0x401000
_LANDING_PAD_ADDRESS = 0x401008


def test_cfg_exception_helpers_contract() -> None:
    binary = _InMemoryElfExceptionBinary()
    cfg = ControlFlowGraph(function_address=_FUNCTION_ADDRESS, function_name="main")
    cfg.add_block(BasicBlock(address=_LANDING_PAD_ADDRESS, size=4))

    edges = detect_exception_edges(binary, cfg, _FUNCTION_ADDRESS)

    expect(len(edges) == 1)
    expect(edges[0].from_address == _FUNCTION_ADDRESS)
    expect(edges[0].to_address == _LANDING_PAD_ADDRESS)
    expect(edges[0].action == "catch")
    expect(cfg.get_block(_LANDING_PAD_ADDRESS).block_type.value == "landing_pad")
    expect(cfg.get_block(_LANDING_PAD_ADDRESS).metadata["is_landing_pad"] is True)
