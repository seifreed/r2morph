from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.session import MorphSession
from tests.utils.assertions import expect


def test_session_checkpoint_and_finalize(tmp_path: Path) -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    session = MorphSession(working_dir=tmp_path)
    working_copy = session.start(source)
    expect(working_copy.exists())

    cp = session.checkpoint("before_mutation", "pre-mutation")
    expect(cp.name == "before_mutation")

    mutation = NopInsertionPass()
    result = session.apply_mutation(mutation, "nop insertion")
    expect(not ("mutations_applied" not in result))

    out_path = tmp_path / "final.bin"
    expect(not (session.finalize(out_path) is not True))
    expect(out_path.exists())

    expect(not (session.rollback_to("before_mutation") is not True))

    session.cleanup(keep_checkpoints=True)
    # After cleanup, current_binary is None so get_current_path() raises
    expect(not (session.current_binary is not None))
