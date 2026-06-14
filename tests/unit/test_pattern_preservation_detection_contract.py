"""Contract tests for pattern preservation detection helpers."""

from __future__ import annotations

from dataclasses import dataclass

from r2morph.analysis.pattern_preservation_detection import (
    detect_exception_patterns,
    detect_jump_table_patterns,
    detect_plt_got_patterns,
    detect_tail_call_patterns,
)
from r2morph.analysis.pattern_preservation_models import PatternType


@dataclass
class _Pad:
    address: int
    size: int
    action: object


@dataclass
class _Frame:
    function_start: int
    function_end: int
    landing_pads: list[_Pad]


@dataclass
class _Action:
    value: str


class _ExceptionReader:
    def read_exception_frames(self):
        return {0x1000: _Frame(0x1000, 0x1100, [_Pad(0x1010, 4, _Action("landing"))])}


@dataclass
class _JumpTable:
    table_address: int
    entries: list[int]
    case_count: int
    is_dense: bool
    bounds_check_register: str
    unique_targets: list[int]


@dataclass
class _Jump:
    address: int
    jump_type: str


class _SwitchAnalyzer:
    def detect_switch_pattern(self, func_addr: int):
        return (
            [_JumpTable(0x2000, [1, 2], 2, True, "eax", [0x2010])],
            [_Jump(0x2020, "indirect")],
        )

    def detect_plt_got_thunks(self):
        return {0x3000: {"name": "puts"}}

    def detect_tail_calls(self, func_addr: int):
        return [(0x4000, 0x4010)]


class _Binary:
    def get_functions(self):
        return [{"offset": 0x2000}]


class _Manager:
    def __init__(self) -> None:
        self.binary = _Binary()
        self._patterns = []
        self._switch_analyzer = None
        self._exception_reader = None


def test_pattern_preservation_detection_contract() -> None:
    manager = _Manager()
    manager._exception_reader = _ExceptionReader()
    detect_exception_patterns(manager)
    assert manager._patterns[0].type == PatternType.EXCEPTION_HANDLER
    assert manager._patterns[1].type == PatternType.LANDING_PAD

    manager = _Manager()
    manager._switch_analyzer = _SwitchAnalyzer()
    detect_jump_table_patterns(manager)
    assert any(pattern.type == PatternType.JUMP_TABLE for pattern in manager._patterns)
    assert any(pattern.type == PatternType.JUMP_TABLE_ENTRY for pattern in manager._patterns)
    assert any(pattern.type == PatternType.INDIRECT_JUMP for pattern in manager._patterns)

    manager = _Manager()
    manager._switch_analyzer = _SwitchAnalyzer()
    detect_plt_got_patterns(manager)
    assert any(pattern.type == PatternType.PLT_THUNK for pattern in manager._patterns)

    manager = _Manager()
    manager._switch_analyzer = _SwitchAnalyzer()
    detect_tail_call_patterns(manager)
    assert any(pattern.type == PatternType.TAIL_CALL for pattern in manager._patterns)
