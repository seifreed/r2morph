"""Contract tests for parallel rollback helpers."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from r2morph.core.parallel_planner import PassResult, PassStatus
from r2morph.core.parallel_rollback import rollback_pass_checkpoint
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY


def test_rollback_pass_checkpoint_restores_status_and_checkpoint() -> None:
    with TemporaryDirectory() as tmpdir:
        binary_path = Path(tmpdir) / "binary.bin"
        checkpoint_path = Path(tmpdir) / "checkpoint.bin"
        binary_path.write_bytes(b"before")
        checkpoint_path.write_bytes(b"after")

        result = PassResult(
            **{MUTATION_NAME_KEY: "alpha"},
            status=PassStatus.COMPLETED,
            checkpoint_path=checkpoint_path,
        )
        logger = SimpleNamespace(
            warning=lambda *args, **kwargs: None,
            info=lambda *args, **kwargs: None,
            error=lambda *args, **kwargs: None,
        )

        expect(rollback_pass_checkpoint(binary_path=binary_path, result=result, logger=logger))
        expect(not (result.status is not PassStatus.ROLLED_BACK))
        expect(binary_path.read_bytes() == b"after")


def test_rollback_pass_checkpoint_without_checkpoint_returns_false() -> None:
    logger = SimpleNamespace(
        warning=lambda *args, **kwargs: None,
        info=lambda *args, **kwargs: None,
        error=lambda *args, **kwargs: None,
    )

    result = PassResult(**{MUTATION_NAME_KEY: "beta"}, status=PassStatus.COMPLETED)
    expect(not (rollback_pass_checkpoint(binary_path=Path("test-data/nowhere"), result=result, logger=logger)))
