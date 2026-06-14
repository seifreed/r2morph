"""Contract tests for full CFF patching helpers."""

from __future__ import annotations

from types import SimpleNamespace

from r2morph.mutations.full_cff import DispatcherBlock
from r2morph.mutations.full_cff_patching import patch_function_blocks


class _Binary:
    def __init__(self) -> None:
        self.writes: list[tuple[int, bytes]] = []
        self.reload_called = False

    def get_arch_info(self) -> dict[str, object]:
        return {"arch": "x86_64", "bits": 64}

    def get_function_disasm(self, _func_addr: int):
        return [
            {"offset": 0x1000, "size": 5},
            {"offset": 0x1005, "size": 5},
        ]

    def read_bytes(self, _addr: int, _size: int) -> bytes:
        return b"\x90" * 5

    def write_bytes(self, addr: int, data: bytes) -> bool:
        self.writes.append((addr, data))
        return True

    def reload(self) -> None:
        self.reload_called = True


class _ValidationManager:
    def __init__(self, *, passed: bool) -> None:
        self.passed = passed
        self.captured = []
        self.validated = []

    def capture_structural_baseline(self, binary, func_addr):
        self.captured.append((binary, func_addr))
        return {"baseline": func_addr}

    def validate_mutation(self, binary, payload):
        self.validated.append((binary, payload))
        return SimpleNamespace(passed=self.passed)


class _Session:
    def __init__(self) -> None:
        self.rollbacks = []

    def rollback_to(self, checkpoint):
        self.rollbacks.append(checkpoint)


class _Record:
    def __init__(self, payload):
        self.payload = payload

    def to_dict(self):
        return dict(self.payload)


def test_full_cff_patching_applies_jump_and_records_mutation() -> None:
    binary = _Binary()
    validation_manager = _ValidationManager(passed=True)
    session = _Session()
    records: list[_Record] = []

    def create_mutation_checkpoint(label: str):
        return f"checkpoint:{label}"

    def record_mutation(**kwargs):
        records.append(_Record(kwargs))

    dispatcher_blocks = [
        DispatcherBlock(state_value=0, block_address=0x1000, block_size=0x10),
        DispatcherBlock(state_value=1, block_address=0x2000, block_size=0x10, is_exit=True),
    ]

    patched = patch_function_blocks(
        binary=binary,
        cfg=SimpleNamespace(function_address=0x1000),
        dispatcher_blocks=dispatcher_blocks,
        dispatcher_addr=0x3000,
        validation_manager=validation_manager,
        create_mutation_checkpoint=create_mutation_checkpoint,
        record_mutation=record_mutation,
        session=session,
        records=records,
        rollback_policy="best-effort",
    )

    assert patched == 1
    assert binary.writes and binary.writes[0][0] == 0x100A
    assert validation_manager.captured == [(binary, 0x1000)]
    assert validation_manager.validated
    assert records
    assert records[0].to_dict()["metadata"]["dispatcher_addr"] == 0x3000


def test_full_cff_patching_rolls_back_failed_validation() -> None:
    binary = _Binary()
    validation_manager = _ValidationManager(passed=False)
    session = _Session()
    records: list[_Record] = []

    patched = patch_function_blocks(
        binary=binary,
        cfg=SimpleNamespace(function_address=0x1000),
        dispatcher_blocks=[DispatcherBlock(state_value=0, block_address=0x1000, block_size=0x10)],
        dispatcher_addr=0x3000,
        validation_manager=validation_manager,
        create_mutation_checkpoint=lambda label: f"checkpoint:{label}",
        record_mutation=lambda **kwargs: records.append(_Record(kwargs)),
        session=session,
        records=records,
        rollback_policy="best-effort",
    )

    assert patched == 0
    assert session.rollbacks == ["checkpoint:full_cff"]
    assert binary.reload_called is True
    assert records == []
