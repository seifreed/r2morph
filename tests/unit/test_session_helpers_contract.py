from pathlib import Path

from r2morph.session import Checkpoint
from r2morph.session_helpers import build_checkpoint_path, build_session_metadata


def test_build_checkpoint_path_uses_sequence_and_name() -> None:
    path = build_checkpoint_path(Path("/tmp/session"), 7, "pre_mutation")

    assert path.name == "checkpoint_0007_pre_mutation.bin"


def test_build_session_metadata_serializes_checkpoints() -> None:
    checkpoints = [
        Checkpoint(
            name="cp1",
            timestamp="2026-01-01T00:00:00",
            binary_path=Path("/tmp/cp1.bin"),
            mutations_applied=3,
            description="first",
        )
    ]

    metadata = build_session_metadata("session-1", 9, checkpoints)

    assert metadata == {
        "session_id": "session-1",
        "mutations_count": 9,
        "checkpoints": [
            {
                "name": "cp1",
                "timestamp": "2026-01-01T00:00:00",
                "mutations_applied": 3,
                "description": "first",
            }
        ],
    }
