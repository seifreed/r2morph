"""
Memory manager for batch processing on large binaries.

Extracted from Binary class following Single Responsibility Principle.
Handles mutation tracking and r2 connection reloading to prevent OOM.
"""

import logging
from typing import TYPE_CHECKING

from r2morph.core.constants import BATCH_MUTATION_CHECKPOINT

if TYPE_CHECKING:
    from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class MemoryManager:
    """
    Manages memory usage during batch processing on large binaries.

    Tracks mutations and periodically reloads the r2 connection to
    release accumulated memory in the radare2 process, preventing OOM crashes.
    """

    def __init__(self, batch_size: int = BATCH_MUTATION_CHECKPOINT):
        """
        Initialize MemoryManager.

        Args:
            batch_size: Number of mutations before reloading r2 (default: 1000)
        """
        self._mutation_counter: int = 0
        self._batch_size: int = batch_size

    @property
    def mutation_count(self) -> int:
        """Get the current mutation count."""
        return self._mutation_counter

    @property
    def batch_size(self) -> int:
        """Get the configured batch size."""
        return self._batch_size

    @batch_size.setter
    def batch_size(self, value: int) -> None:
        """Set the batch size."""
        self._batch_size = value

    def reset_counter(self) -> None:
        """Reset the mutation counter to zero."""
        self._mutation_counter = 0

    def track_mutation(self, binary: "Binary") -> None:
        """
        Track a mutation and reload r2 periodically for batch processing.

        This prevents OOM on large binaries by restarting r2 every N mutations.

        Args:
            binary: Binary instance to reload if needed
        """
        if not binary._low_memory:
            return

        self._mutation_counter += 1
        if self._mutation_counter % self._batch_size == 0:
            logger.info(
                f"Batch checkpoint: {self._mutation_counter} mutations applied. "
                f"Reloading r2 to free memory..."
            )
            self._reload_binary(binary)

    def _reload_binary(self, binary: "Binary") -> None:
        """
        Reload r2 connection (close and reopen).

        This is useful for batch processing on large binaries to release
        accumulated memory in radare2 process, preventing OOM crashes.

        Args:
            binary: Binary instance to reload
        """
        logger.debug("Reloading r2 connection to free memory")
        was_analyzed = binary._analyzed
        binary.close()
        binary.open()
        # Restore analyzed state (cache is preserved separately)
        binary._analyzed = was_analyzed

    def force_reload(self, binary: "Binary") -> None:
        """
        Force a reload of the r2 connection.

        Args:
            binary: Binary instance to reload
        """
        self._reload_binary(binary)


# Singleton instance for convenience
_default_memory_manager: MemoryManager | None = None


def get_memory_manager() -> MemoryManager:
    """Get the default MemoryManager instance."""
    global _default_memory_manager
    if _default_memory_manager is None:
        _default_memory_manager = MemoryManager()
    return _default_memory_manager
