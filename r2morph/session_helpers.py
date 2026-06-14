"""Pure helpers for mutation session checkpoint handling."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def build_checkpoint_path(session_dir: Path, checkpoint_seq: int, name: str) -> Path:
    """Build a checkpoint path for a session snapshot."""
    return session_dir / f"checkpoint_{checkpoint_seq:04d}_{name}.bin"


def build_session_metadata(
    session_id: str,
    mutations_count: int,
    checkpoints: list[Any],
) -> dict[str, Any]:
    """Build the serializable metadata payload for a session."""
    return {
        "session_id": session_id,
        "mutations_count": mutations_count,
        "checkpoints": [
            {
                "name": cp.name,
                "timestamp": cp.timestamp,
                "mutations_applied": cp.mutations_applied,
                "description": cp.description,
            }
            for cp in checkpoints
        ],
    }
