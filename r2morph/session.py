"""
Mutation session management with checkpointing and rollback.
"""

import json
import logging
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Checkpoint:
    """Represents a mutation checkpoint."""

    name: str
    timestamp: str
    binary_path: Path
    mutations_applied: int
    description: str


class MorphSession:
    """
    Manages mutation sessions with checkpointing and rollback.

    Allows creating snapshots during mutation process and
    rolling back to previous states if needed.
    """

    def __init__(self, working_dir: Path | None = None):
        """
        Initialize mutation session.

        Args:
            working_dir: Directory for session data
        """
        if working_dir is None:
            import tempfile

            working_dir = Path(tempfile.gettempdir()) / "r2morph_sessions"

        self.working_dir = working_dir
        self.working_dir.mkdir(parents=True, exist_ok=True)

        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = self.working_dir / self.session_id
        self.session_dir.mkdir(exist_ok=True)

        self.checkpoints: list[Checkpoint] = []
        self.current_binary: Path | None = None
        self.mutations_count = 0

        logger.info(f"Created mutation session: {self.session_id}")

    def start(self, original_binary: Path) -> Path:
        """
        Start a new session with original binary.

        Args:
            original_binary: Path to original binary

        Returns:
            Path to working copy
        """
        logger.info(f"Starting session with {original_binary.name}")

        working_copy = self.session_dir / "current.bin"
        shutil.copy2(original_binary, working_copy)

        self.current_binary = working_copy

        self.checkpoint("initial", "Original binary")

        return working_copy

    def checkpoint(self, name: str, description: str = "") -> Checkpoint:
        """
        Create a checkpoint of current state.

        Args:
            name: Checkpoint name
            description: Description

        Returns:
            Checkpoint object
        """
        if self.current_binary is None:
            raise ValueError("No active binary in session")

        logger.info(f"Creating checkpoint: {name}")

        checkpoint_path = self.session_dir / f"checkpoint_{name}.bin"
        shutil.copy2(self.current_binary, checkpoint_path)

        checkpoint = Checkpoint(
            name=name,
            timestamp=datetime.now().isoformat(),
            binary_path=checkpoint_path,
            mutations_applied=self.mutations_count,
            description=description,
        )

        self.checkpoints.append(checkpoint)

        self._save_metadata()

        return checkpoint

    def rollback_to(self, checkpoint_name: str) -> bool:
        """
        Rollback to a previous checkpoint.

        Args:
            checkpoint_name: Name of checkpoint

        Returns:
            True if successful
        """
        logger.info(f"Rolling back to checkpoint: {checkpoint_name}")

        checkpoint = None
        for cp in self.checkpoints:
            if cp.name == checkpoint_name:
                checkpoint = cp
                break

        if checkpoint is None:
            logger.error(f"Checkpoint '{checkpoint_name}' not found")
            return False

        if not checkpoint.binary_path.exists():
            logger.error(f"Checkpoint file not found: {checkpoint.binary_path}")
            return False

        shutil.copy2(checkpoint.binary_path, self.current_binary)
        self.mutations_count = checkpoint.mutations_applied

        logger.info(f"Rolled back to checkpoint '{checkpoint_name}'")
        return True

    def apply_mutation(self, mutation_pass: Any, description: str = "") -> dict[str, Any]:
        """
        Apply a mutation pass and track it.

        Args:
            mutation_pass: Mutation pass instance
            description: Description of mutation

        Returns:
            Mutation result dict
        """
        from r2morph.core.binary import Binary

        logger.info(f"Applying mutation: {mutation_pass.name}")

        with Binary(self.current_binary, writable=True) as binary:
            binary.analyze()
            result = mutation_pass.apply(binary)

        mutations_applied = result.get("mutations_applied", 0)
        self.mutations_count += mutations_applied

        logger.info(f"Applied {mutations_applied} mutations (total: {self.mutations_count})")

        return result

    def list_checkpoints(self) -> list[Checkpoint]:
        """
        List all checkpoints in this session.

        Returns:
            List of checkpoints
        """
        return self.checkpoints.copy()

    def get_current_path(self) -> Path:
        """
        Get path to current binary.

        Returns:
            Path to current binary
        """
        if self.current_binary is None:
            raise ValueError("No active binary in session")

        return self.current_binary

    def finalize(self, output_path: Path) -> bool:
        """
        Finalize session and save result.

        Args:
            output_path: Final output path

        Returns:
            True if successful
        """
        logger.info(f"Finalizing session to {output_path}")

        if self.current_binary is None:
            return False

        shutil.copy2(self.current_binary, output_path)

        self.checkpoint("final", f"Final output: {output_path.name}")

        logger.info(f"Session finalized: {self.mutations_count} total mutations")

        return True

    def cleanup(self, keep_checkpoints: bool = False):
        """
        Clean up session files.

        Args:
            keep_checkpoints: Keep checkpoint files
        """
        logger.info("Cleaning up session")

        if not keep_checkpoints:
            shutil.rmtree(self.session_dir, ignore_errors=True)
        else:
            if self.current_binary and self.current_binary.exists():
                self.current_binary.unlink()

    def _save_metadata(self):
        """Save session metadata to JSON."""
        metadata = {
            "session_id": self.session_id,
            "mutations_count": self.mutations_count,
            "checkpoints": [
                {
                    "name": cp.name,
                    "timestamp": cp.timestamp,
                    "mutations_applied": cp.mutations_applied,
                    "description": cp.description,
                }
                for cp in self.checkpoints
            ],
        }

        metadata_file = self.session_dir / "session.json"
        with open(metadata_file, "w") as f:
            json.dump(metadata, f, indent=2)
