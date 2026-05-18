"""Regression: same-named MorphSession checkpoints must not clobber.

checkpoint() derived the snapshot file path solely from the name
(checkpoint_<name>.bin), so two checkpoints created with the same name
(apply_mutation always names its pre-state "pre_mutation") shared one
file: the second shutil.copy2 silently overwrote the first's snapshot
while both kept separate Checkpoint entries. _remove_checkpoint then
deleted by name, dropping unrelated same-named checkpoints and their
shared file.

No mocks (CLAUDE.md SS4): a real MorphSession over real files in
tmp_path.
"""

from pathlib import Path

from r2morph.session import MorphSession


def _new_session(tmp_path: Path) -> tuple[MorphSession, Path]:
    orig = tmp_path / "orig.bin"
    orig.write_bytes(b"ORIG" + b"\x00" * 60)
    session = MorphSession(working_dir=tmp_path / "sessions")
    session.start(orig)
    assert session.current_binary is not None
    return session, session.current_binary


def test_same_named_checkpoints_retain_distinct_snapshots(tmp_path: Path) -> None:
    session, current = _new_session(tmp_path)

    current.write_bytes(b"STATE_A" + b"\x00" * 57)
    cp_a = session.checkpoint("dup")

    current.write_bytes(b"STATE_B" + b"\x00" * 57)
    cp_b = session.checkpoint("dup")

    assert cp_a.binary_path != cp_b.binary_path
    assert cp_a.binary_path.read_bytes().startswith(b"STATE_A")
    assert cp_b.binary_path.read_bytes().startswith(b"STATE_B")

    current.write_bytes(b"STATE_C" + b"\x00" * 57)
    assert session.rollback_to("dup") is True
    assert session.current_binary is not None
    assert session.current_binary.read_bytes().startswith(b"STATE_B")


def test_remove_checkpoint_is_identity_scoped(tmp_path: Path) -> None:
    session, current = _new_session(tmp_path)

    current.write_bytes(b"A" * 16)
    cp_a = session.checkpoint("dup")
    current.write_bytes(b"B" * 16)
    cp_b = session.checkpoint("dup")

    session._remove_checkpoint(cp_b)

    assert cp_b not in session.checkpoints
    assert cp_a in session.checkpoints
    assert cp_a.binary_path.exists()
    assert cp_a.binary_path.read_bytes().startswith(b"A")
