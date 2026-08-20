from __future__ import annotations

from dataclasses import dataclass, field

from r2morph.analysis.call_graph_entry_points import find_entry_points
from tests.utils.assertions import expect


@dataclass
class DummyGraph:
    nodes: set[int] = field(default_factory=set)

    def get_entry_points(self) -> list[int]:
        return [0x5000]


@dataclass
class DummyBinary:
    _symbols: dict[str, object] = field(default_factory=dict)


def test_call_graph_entry_point_detection_prefers_symbol_order() -> None:
    binary = DummyBinary(
        _symbols={
            "entry0": {"offset": 0x1000},
            "main": {"offset": 0x2000},
            "__libc_csu_init": {"offset": 0x3000},
            "_init": {"offset": 0x4000},
        }
    )
    cg = DummyGraph(nodes={0x1000, 0x2000, 0x3000, 0x4000})

    expect(find_entry_points(binary, cg) == [4096, 8192, 12288, 16384])


def test_call_graph_entry_point_detection_falls_back_to_graph_entries() -> None:
    binary = DummyBinary(_symbols={})
    cg = DummyGraph(nodes=set())

    expect(find_entry_points(binary, cg) == [20480])
