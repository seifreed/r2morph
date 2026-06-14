"""Contract tests for parallel rollback helpers."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from r2morph.core.parallel_planner import PassResult, PassStatus
from r2morph.core.parallel_rollback import rollback_pass_checkpoint


def test_rollback_pass_checkpoint_restores_status_and_checkpoint() -> None:
    with TemporaryDirectory() as tmpdir:
        binary_path = Path(tmpdir) / "binary.bin"
        checkpoint_path = Path(tmpdir) / "checkpoint.bin"
        binary_path.write_bytes(b"before")
        checkpoint_path.write_bytes(b"after")

        result = PassResult(
            pass_name="alpha",
            status=PassStatus.COMPLETED,
            checkpoint_path=checkpoint_path,
        )
        logger = SimpleNamespace(
            warning=lambda *args, **kwargs: None,
            info=lambda *args, **kwargs: None,
            error=lambda *args, **kwargs: None,
        )

        assert rollback_pass_checkpoint(binary_path=binary_path, result=result, logger=logger)
        assert result.status is PassStatus.ROLLED_BACK
        assert binary_path.read_bytes() == b"after"


def test_rollback_pass_checkpoint_without_checkpoint_returns_false() -> None:
    logger = SimpleNamespace(
        warning=lambda *args, **kwargs: None,
        info=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )

    result = PassResult(pass_name="beta", status=PassStatus.COMPLETED)
    assert not rollback_pass_checkpoint(binary_path=Path("/tmp/nowhere"), result=result, logger=logger)
