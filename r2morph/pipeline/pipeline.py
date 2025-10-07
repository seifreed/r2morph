"""
Pipeline for orchestrating multiple transformation passes.
"""

import logging
from typing import Any

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


class Pipeline:
    """
    Manages and executes a sequence of mutation passes.

    The pipeline runs mutation passes in order, allowing each pass
    to transform the binary independently.

    Attributes:
        passes: List of mutation passes to execute
    """

    def __init__(self):
        """Initialize an empty pipeline."""
        self.passes: list[MutationPass] = []

    def add_pass(self, mutation_pass: MutationPass) -> "Pipeline":
        """
        Add a mutation pass to the pipeline.

        Args:
            mutation_pass: Mutation pass to add

        Returns:
            Self for method chaining
        """
        self.passes.append(mutation_pass)
        logger.debug(f"Added pass: {mutation_pass.name}")
        return self

    def remove_pass(self, pass_name: str) -> bool:
        """
        Remove a pass by name.

        Args:
            pass_name: Name of the pass to remove

        Returns:
            True if pass was removed, False if not found
        """
        for i, p in enumerate(self.passes):
            if p.name == pass_name:
                self.passes.pop(i)
                logger.debug(f"Removed pass: {pass_name}")
                return True
        return False

    def clear(self):
        """Clear all passes from the pipeline."""
        self.passes.clear()
        logger.debug("Pipeline cleared")

    def run(self, binary: Binary) -> dict[str, Any]:
        """
        Execute all passes in the pipeline on the given binary.

        Args:
            binary: Binary instance to transform

        Returns:
            Dictionary with statistics from all passes
        """
        if not self.passes:
            logger.warning("Pipeline is empty, no transformations will be applied")
            return {"passes_run": 0, "total_mutations": 0}

        logger.info(f"Running pipeline with {len(self.passes)} passes")

        results = {
            "passes_run": 0,
            "total_mutations": 0,
            "pass_results": {},
        }

        for i, mutation_pass in enumerate(self.passes):
            logger.info(f"Running pass {i + 1}/{len(self.passes)}: {mutation_pass.name}")

            try:
                pass_result = mutation_pass.run(binary)
                results["passes_run"] += 1
                results["total_mutations"] += pass_result.get("mutations_applied", 0)
                results["pass_results"][mutation_pass.name] = pass_result

                logger.info(
                    f"Pass {mutation_pass.name} complete: "
                    f"{pass_result.get('mutations_applied', 0)} mutations"
                )
            except Exception as e:
                logger.error(f"Pass {mutation_pass.name} failed: {e}")
                results["pass_results"][mutation_pass.name] = {"error": str(e)}

        logger.info(f"Pipeline complete: {results['total_mutations']} total mutations")
        return results

    def get_pass_names(self) -> list[str]:
        """Get list of pass names in the pipeline."""
        return [p.name for p in self.passes]

    def __len__(self) -> int:
        """Get number of passes in pipeline."""
        return len(self.passes)

    def __repr__(self) -> str:
        return f"<Pipeline with {len(self.passes)} passes>"
