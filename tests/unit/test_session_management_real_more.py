from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.session import MorphSession


def test_session_checkpoint_and_finalize(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    session = MorphSession(working_dir=tmp_path)
    working_copy = session.start(source)
    assert working_copy.exists()

    cp = session.checkpoint("before_mutation", "pre-mutation")
    assert cp.name == "before_mutation"

    mutation = NopInsertionPass()
    result = session.apply_mutation(mutation, "nop insertion")
    assert "mutations_applied" in result

    out_path = tmp_path / "final.bin"
    assert session.finalize(out_path) is True
    assert out_path.exists()

    assert session.rollback_to("before_mutation") is True

    session.cleanup(keep_checkpoints=True)
    assert not session.get_current_path().exists()
