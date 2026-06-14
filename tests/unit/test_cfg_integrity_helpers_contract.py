from types import SimpleNamespace

from r2morph.validation.cfg_integrity_helpers import create_cfg_snapshot, validate_cfg_snapshot
from r2morph.validation.cfg_integrity_models import CFGSnapshot, IntegrityStatus


class _FakeBlock:
    def __init__(self, size: int, is_entry: bool = False, is_exit: bool = False, instructions=None) -> None:
        self.size = size
        self.is_entry = is_entry
        self.is_exit = is_exit
        self.instructions = instructions or []


def test_create_cfg_snapshot_collects_edges_and_patterns() -> None:
    cfg = SimpleNamespace(
        blocks={
            0x1000: _FakeBlock(4, is_entry=True, instructions=[{"offset": 0x1000, "type": "jmp", "disasm": "jmp 0x2000"}]),
            0x2000: _FakeBlock(4, is_exit=True),
        },
        edges=[(0x1000, 0x2000)],
        exception_edges=[SimpleNamespace(from_address=0x2000, to_address=0x3000)],
    )

    class _Builder:
        def build_cfg(self, function_address: int, func_name: str):  # noqa: ARG002
            return cfg

    class _Manager:
        _analyzed = True

        def get_patterns_in_range(self, start: int, end: int):  # noqa: ARG002
            return [SimpleNamespace(start_address=0x1000, end_address=0x1100, type=SimpleNamespace(value="jump_table"), source="test")]

    snapshot = create_cfg_snapshot(_Builder(), _Manager(), 0x1000)

    assert snapshot is not None
    assert snapshot.entry_block == 0x1000
    assert snapshot.exit_blocks == [0x2000]
    assert snapshot.edges == [(0x1000, 0x2000, "normal"), (0x2000, 0x3000, "exception")]
    assert snapshot.preserved_patterns[0].start_address == 0x1000


def test_validate_cfg_snapshot_reports_broken_edges_and_targets() -> None:
    snapshot = CFGSnapshot(
        function_address=0x1000,
        blocks={
            0x1000: {
                "address": 0x1000,
                "size": 4,
                "instructions": [
                    {"address": 0x1000, "mnemonic": "jmp", "disasm": "jmp 0x5000"},
                ],
                "is_entry": True,
                "is_exit": False,
            }
        },
        edges=[(0x1000, 0x2000, "exception")],
        entry_block=0x1000,
        exit_blocks=[],
        preserved_patterns=[],
    )

    report = validate_cfg_snapshot(snapshot)

    assert report.valid is False
    assert any(v.status == IntegrityStatus.BROKEN_EDGE for v in report.violations)
    assert any(v.status == IntegrityStatus.INVALID_TARGET for v in report.violations)
