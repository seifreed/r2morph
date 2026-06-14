"""Contract tests for parallel pass execution helpers."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from r2morph.core.parallel_pass_execution import execute_checkpointed_pass


class DummyPass:
    def __init__(self) -> None:
        self.name = "alpha"
        self.calls = 0

    def apply(self, binary):
        self.calls += 1
        binary.touched = True
        return {"mutations_applied": 2}


class DummyLock:
    def __init__(self) -> None:
        self.locked = False

    def acquire(self) -> bool:
        self.locked = True
        return True

    def is_locked(self) -> bool:
        return self.locked

    def release(self) -> None:
        self.locked = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.release()
        return False


def test_execute_checkpointed_pass_returns_completed_result() -> None:
    with TemporaryDirectory() as tmpdir:
        binary_path = Path(tmpdir) / "binary.bin"
        binary_path.write_bytes(b"abc")
        binary = SimpleNamespace(path=binary_path, touched=False)
        pass_obj = DummyPass()
        lock = DummyLock()
        callback_calls: list[tuple[str, float]] = []

        result = execute_checkpointed_pass(
            binary=binary,
            pass_obj=pass_obj,
            checkpoint_dir=Path(tmpdir),
            use_checkpoints=True,
            file_lock=lock,
            use_file_lock=True,
            binary_mutation_lock=DummyLock(),
            progress_callback=lambda name, progress: callback_calls.append((name, progress)),
            logger=SimpleNamespace(debug=lambda *args, **kwargs: None, error=lambda *args, **kwargs: None),
        )

        assert result.status.value == "completed"
        assert result.mutations_applied == 2
        assert result.checkpoint_path is not None
        assert binary.touched is True
        assert callback_calls == [("alpha", 0.0), ("alpha", 1.0)]
