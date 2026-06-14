from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.session import MorphSession
from r2morph.session_mutation_flow import apply_mutation


def test_session_mutation_flow_applies_and_tracks_mutations(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    session = MorphSession(working_dir=tmp_path)
    session.start(source)

    result = apply_mutation(session, NopInsertionPass(), "nop insertion")

    assert "mutations_applied" in result
    assert session.mutations_count == result["mutations_applied"]
    assert session.current_binary is not None
    assert any(cp.name == "pre_mutation" for cp in session.checkpoints)
