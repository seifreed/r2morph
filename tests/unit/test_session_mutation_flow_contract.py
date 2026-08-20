from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.session import MorphSession
from r2morph.session_mutation_flow import apply_mutation
from tests.utils.assertions import expect


def test_session_mutation_flow_applies_and_tracks_mutations(tmp_path: Path) -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    session = MorphSession(working_dir=tmp_path)
    session.start(source)

    result = apply_mutation(session, NopInsertionPass(), "nop insertion")

    expect(not ("mutations_applied" not in result))
    expect(session.mutations_count == result["mutations_applied"])
    expect(session.current_binary is not None)
    expect(any(cp.name == "pre_mutation" for cp in session.checkpoints))
