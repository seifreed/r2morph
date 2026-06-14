"""Contract tests for parallel checkpoint helpers."""

from __future__ import annotations

from pathlib import Path

from r2morph.core.parallel_checkpointing import has_failures, rollback_checkpoint, save_checkpoint
from r2morph.core.parallel_planner import PassResult, PassStatus


class _Logger:
    def __init__(self) -> None:
        self.messages: list[tuple[str, str]] = []

    def debug(self, message: str) -> None:
        self.messages.append(("debug", message))

    def info(self, message: str) -> None:
        self.messages.append(("info", message))

    def warning(self, message: str) -> None:
        self.messages.append(("warning", message))

    def error(self, message: str) -> None:
        self.messages.append(("error", message))


def test_checkpoint_helpers_round_trip(tmp_path: Path) -> None:
    binary = tmp_path / "binary.bin"
    binary.write_bytes(b"abc")
    checkpoint_dir = tmp_path / "checkpoints"
    checkpoint_dir.mkdir()
    logger = _Logger()

    checkpoint = save_checkpoint(binary, checkpoint_dir, "phase1", logger)
    assert checkpoint.exists()

    binary.write_bytes(b"mutated")
    assert rollback_checkpoint(binary, checkpoint, logger) is True
    assert binary.read_bytes() == b"abc"

    results = {
        "ok": PassResult(pass_name="ok", status=PassStatus.COMPLETED),
        "fail": PassResult(pass_name="fail", status=PassStatus.FAILED),
    }
    assert has_failures(results) is True
