"""Contract tests for parallel checkpoint helpers."""

from __future__ import annotations

from pathlib import Path

from r2morph.core.parallel_checkpointing import has_failures, rollback_checkpoint, save_checkpoint
from r2morph.core.parallel_planner import PassResult, PassStatus
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY


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
    expect(checkpoint.exists())

    binary.write_bytes(b"mutated")
    expect(not (rollback_checkpoint(binary, checkpoint, logger) is not True))
    expect(binary.read_bytes() == b"abc")

    results = {
        "ok": PassResult(**{MUTATION_NAME_KEY: "ok"}, status=PassStatus.COMPLETED),
        "fail": PassResult(**{MUTATION_NAME_KEY: "fail"}, status=PassStatus.FAILED),
    }
    expect(not (has_failures(results) is not True))
