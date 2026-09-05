import struct

from r2morph.analysis.cfg_exception_helpers import detect_exception_edges
from r2morph.analysis.cfg_models import BasicBlock, ControlFlowGraph
from tests._doubles.in_memory_pe_pdata_binary import InMemoryPEUnwindBinary
from tests.unit.test_exception_reader_contract import _InMemoryElfExceptionBinary, _InMemoryMachoExceptionBinary
from tests.utils.assertions import expect

_FUNCTION_ADDRESS = 0x401000
_LANDING_PAD_ADDRESS = 0x401008
_PE_FUNCTION_ADDRESS = 0x1000
_PE_HANDLER_ADDRESS = 0x1100


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


def test_cfg_exception_helpers_pe_unwind_handler_adds_exception_edge() -> None:
    pdata = struct.pack("<III", 0x1000, 0x1050, 0x5000)
    xdata = bytes((0x08, 0x00, 0x00, 0x00)) + struct.pack("<I", 0x1100)
    binary = InMemoryPEUnwindBinary(pdata_bytes=pdata, xdata_bytes=xdata)
    cfg = ControlFlowGraph(function_address=_PE_FUNCTION_ADDRESS, function_name="pe_handler")
    cfg.add_block(BasicBlock(address=_PE_HANDLER_ADDRESS, size=4))

    edges = detect_exception_edges(binary, cfg, _PE_FUNCTION_ADDRESS)

    expect(len(edges) == 1)
    expect(edges[0].to_address == _PE_HANDLER_ADDRESS)
    expect(edges[0].action == "catch")
    expect(cfg.get_block(_PE_HANDLER_ADDRESS).block_type.value == "landing_pad")


def test_cfg_exception_helpers_macho_eh_frame_adds_exception_edge() -> None:
    binary = _InMemoryMachoExceptionBinary()
    cfg = ControlFlowGraph(function_address=_FUNCTION_ADDRESS, function_name="macho_main")
    cfg.add_block(BasicBlock(address=_LANDING_PAD_ADDRESS, size=4))

    edges = detect_exception_edges(binary, cfg, _FUNCTION_ADDRESS)

    expect(len(edges) == 1)
    expect(edges[0].from_address == _FUNCTION_ADDRESS)
    expect(edges[0].to_address == _LANDING_PAD_ADDRESS)
    expect(edges[0].action == "catch")
