"""
Main morphing engine for binary transformations.
"""

import logging
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass
from r2morph.pipeline.pipeline import Pipeline

logger = logging.getLogger(__name__)


class MorphEngine:
    """
    Main engine for orchestrating binary transformations.

    The engine manages the binary analysis, applies mutation passes through
    a pipeline, and handles the output generation.

    Attributes:
        binary: Binary instance being transformed
        pipeline: Transformation pipeline
        config: Engine configuration
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the MorphEngine.

        Args:
            config: Optional configuration dictionary
        """
        self.binary: Binary | None = None
        self.pipeline = Pipeline()
        self.config = config or {}
        self._stats: dict[str, Any] = {}

    def load_binary(self, path: str | Path, writable: bool = True) -> "MorphEngine":
        """
        Load a binary for transformation.

        Args:
            path: Path to binary file
            writable: Open in write mode for mutations (default: True)

        Returns:
            Self for method chaining
        """
        logger.info(f"Loading binary: {path}")

        if writable:
            import shutil
            import tempfile
            from pathlib import Path

            original_path = Path(path)
            temp_dir = Path(tempfile.gettempdir()) / "r2morph"
            temp_dir.mkdir(exist_ok=True)

            working_copy = temp_dir / f"{original_path.name}.working"
            shutil.copy2(original_path, working_copy)

            logger.debug(f"Created working copy: {working_copy}")

            self.binary = Binary(working_copy, writable=True)
            self._original_path = original_path
        else:
            self.binary = Binary(path, writable=False)
            self._original_path = None

        self.binary.open()
        return self

    def analyze(self, level: str = "aaa") -> "MorphEngine":
        """
        Analyze the loaded binary.

        Args:
            level: Analysis level (aa, aaa, aaaa)

        Returns:
            Self for method chaining
        """
        if not self.binary:
            raise RuntimeError("No binary loaded. Call load_binary() first.")

        logger.info("Analyzing binary...")
        self.binary.analyze(level)

        functions = self.binary.get_functions()
        arch_info = self.binary.get_arch_info()

        self._stats = {
            "functions": len(functions),
            "arch": arch_info.get("arch"),
            "bits": arch_info.get("bits"),
            "format": arch_info.get("format"),
        }

        logger.info(f"Analysis complete. Found {len(functions)} functions")
        logger.debug(f"Architecture: {arch_info}")

        return self

    def add_mutation(self, mutation: MutationPass) -> "MorphEngine":
        """
        Add a mutation pass to the pipeline.

        Args:
            mutation: Mutation pass to add

        Returns:
            Self for method chaining
        """
        self.pipeline.add_pass(mutation)
        logger.debug(f"Added mutation: {mutation.__class__.__name__}")
        return self

    def run(self) -> dict[str, Any]:
        """
        Run the transformation pipeline on the binary.

        Returns:
            Dictionary with transformation statistics and results
        """
        if not self.binary:
            raise RuntimeError("No binary loaded. Call load_binary() first.")

        if not self.binary.is_analyzed():
            logger.warning("Binary not analyzed. Running automatic analysis...")
            self.analyze()

        logger.info("Starting transformation pipeline...")
        result = self.pipeline.run(self.binary)

        logger.info("Transformation complete")
        return {**self._stats, **result}

    def save(self, output_path: str | Path):
        """
        Save the transformed binary.

        Args:
            output_path: Output file path
        """
        if not self.binary:
            raise RuntimeError("No binary loaded.")

        import shutil
        from pathlib import Path

        output_path = Path(output_path)

        logger.info(f"Saving transformed binary to: {output_path}")

        shutil.copy2(self.binary.path, output_path)
        logger.info(f"Binary successfully saved to: {output_path}")

    def close(self):
        """Close and cleanup resources."""
        if self.binary:
            self.binary.close()
            self.binary = None

    def get_stats(self) -> dict[str, Any]:
        """Get transformation statistics."""
        return self._stats

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
