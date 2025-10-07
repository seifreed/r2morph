"""
Base class for mutation passes.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class MutationPass(ABC):
    """
    Abstract base class for all mutation passes.

    A mutation pass analyzes a binary and applies specific transformations
    while preserving semantic equivalence.

    Subclasses must implement the `apply()` method.

    Attributes:
        name: Name of the mutation pass
        enabled: Whether this pass is enabled
        config: Configuration dictionary for the pass
    """

    def __init__(self, name: str, config: dict[str, Any] | None = None):
        """
        Initialize a mutation pass.

        Args:
            name: Name of this pass
            config: Optional configuration dictionary
        """
        self.name = name
        self.enabled = True
        self.config = config or {}
        self._stats: dict[str, Any] = {}

    @abstractmethod
    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply mutations to the binary.

        This method must be implemented by subclasses.

        Args:
            binary: Binary instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        pass

    def run(self, binary: Binary) -> dict[str, Any]:
        """
        Run the mutation pass on a binary.

        Args:
            binary: Binary instance to mutate

        Returns:
            Dictionary with mutation results and statistics
        """
        if not self.enabled:
            logger.info(f"Pass {self.name} is disabled, skipping")
            return {"mutations_applied": 0, "skipped": True}

        logger.debug(f"Running mutation pass: {self.name}")

        try:
            result = self.apply(binary)
            self._stats = result
            return result
        except Exception as e:
            logger.error(f"Error in mutation pass {self.name}: {e}")
            raise

    def enable(self):
        """Enable this mutation pass."""
        self.enabled = True
        logger.debug(f"Enabled pass: {self.name}")

    def disable(self):
        """Disable this mutation pass."""
        self.enabled = False
        logger.debug(f"Disabled pass: {self.name}")

    def get_stats(self) -> dict[str, Any]:
        """Get statistics from the last run."""
        return self._stats

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} enabled={self.enabled}>"
