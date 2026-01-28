"""
Main morphing engine for binary transformations.
"""

import logging
import os
import platform
import shutil
import tempfile
from pathlib import Path
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.constants import (
    BATCH_MUTATION_CHECKPOINT,
    LARGE_BINARY_THRESHOLD_MB,
    LARGE_FUNCTION_COUNT_THRESHOLD,
    MANY_FUNCTIONS_THRESHOLD,
    MEDIUM_FUNCTION_COUNT_THRESHOLD,
    VERY_MANY_FUNCTIONS_THRESHOLD,
)
from r2morph.mutations.base import MutationPass
from r2morph.pipeline.pipeline import Pipeline
from r2morph.platform.codesign import CodeSigner

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
        self._memory_efficient_mode = False

    @property
    def mutations(self) -> list[MutationPass]:
        """
        Get list of registered mutation passes.

        Returns:
            List of mutation passes in the pipeline
        """
        return self.pipeline.passes

    def _should_use_low_memory(self, path: Path) -> bool:
        """Determine if low-memory mode should be enabled based on file size."""
        binary_size_mb = os.path.getsize(path) / (1024 * 1024)
        return binary_size_mb > LARGE_BINARY_THRESHOLD_MB

    def _create_working_copy(self, original_path: Path) -> Path:
        """Create a temporary working copy of the binary."""
        temp_dir = Path(tempfile.gettempdir()) / "r2morph"
        temp_dir.mkdir(exist_ok=True)
        working_copy = temp_dir / f"{original_path.name}.working"
        shutil.copy2(original_path, working_copy)
        return working_copy

    def _get_binary_size_mb(self, path: Path) -> float:
        """Get binary file size in megabytes."""
        return os.path.getsize(path) / (1024 * 1024)

    def _should_enable_memory_efficient_mode(
        self, binary_size_mb: float, function_count: int
    ) -> bool:
        """Determine if memory-efficient mode should be enabled."""
        return (
            binary_size_mb > LARGE_BINARY_THRESHOLD_MB
            or function_count > LARGE_FUNCTION_COUNT_THRESHOLD
        )

    def load_binary(self, path: str | Path, writable: bool = True) -> "MorphEngine":
        """
        Load a binary for transformation.

        Args:
            path: Path to binary file
            writable: Open in write mode for mutations (default: True)

        Returns:
            Self for method chaining
        """
        path = Path(path)
        logger.info(f"Loading binary: {path}")

        if writable:
            working_copy = self._create_working_copy(path)
            logger.debug(f"Created working copy: {working_copy}")
            self._original_path = path
            target_path = working_copy
        else:
            self._original_path = None
            target_path = path

        low_memory = self._should_use_low_memory(target_path)
        self.binary = Binary(target_path, writable=writable, low_memory=low_memory)
        self.binary.open()

        return self

    def analyze(self, level: str = "auto") -> "MorphEngine":
        """
        Analyze the loaded binary.

        Args:
            level: Analysis level (aa, aac, aaa, aaaa, or "auto" for adaptive)
                - aa: Basic analysis (fast, ~5s for 7k functions)
                - aac: Call analysis (fast, finds most functions)
                - aaa: Full analysis (SLOW on large binaries, recommended < 1000 functions)
                - aaaa: Experimental (very slow)
                - auto: Automatically choose based on binary size (default)

        Returns:
            Self for method chaining
        """
        if not self.binary:
            raise RuntimeError("No binary loaded. Call load_binary() first.")

        # Auto-detect best analysis level based on function count and size
        if level == "auto":
            level = self._auto_detect_analysis_level()
        else:
            # Manual level specified
            logger.info(f"Analyzing binary with level: {level}...")
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

        # Enable memory-efficient mode for large binaries to prevent OOM
        binary_size_mb = self._get_binary_size_mb(self.binary.path)
        if self._should_enable_memory_efficient_mode(binary_size_mb, len(functions)):
            self._memory_efficient_mode = True
            logger.warning(
                f"Large binary detected ({binary_size_mb:.1f} MB, {len(functions)} functions). "
                f"Enabling memory-efficient mode to prevent OOM crashes."
            )
            logger.info(
                f"Memory-efficient mode: reduced mutations per function, "
                f"batch processing with r2 restarts every {BATCH_MUTATION_CHECKPOINT} mutations."
            )

        return self

    def _auto_detect_analysis_level(self) -> str:
        """Auto-detect optimal analysis level based on binary complexity."""
        import time

        # Step 1: Quick basic analysis to count functions
        logger.info("Running quick analysis to estimate complexity...")
        start = time.time()
        self.binary.analyze("aa")
        quick_funcs = len(self.binary.get_functions())
        aa_time = time.time() - start

        # Calculate average function size
        binary_size_mb = self._get_binary_size_mb(self.binary.path)
        avg_func_size = (binary_size_mb * 1024 * 1024) / quick_funcs if quick_funcs > 0 else 0

        logger.info(
            f"Binary stats: {quick_funcs} functions, {binary_size_mb:.1f} MB, "
            f"avg {avg_func_size:.0f} bytes/func (aa took {aa_time:.1f}s)"
        )

        # Step 2: Decide analysis level based on complexity
        if quick_funcs > VERY_MANY_FUNCTIONS_THRESHOLD:
            level = "aa"  # Already done
            logger.warning(
                f"Very large binary ({quick_funcs} functions). "
                f"Using fast analysis level 'aa' (already complete)."
            )
        elif quick_funcs > MANY_FUNCTIONS_THRESHOLD:
            level = "aac"  # Add call analysis
            logger.warning(
                f"Large binary ({quick_funcs} functions). "
                f"Using 'aac' analysis (adds ~10-20s for call analysis)."
            )
            self.binary.analyze("aac")
        elif quick_funcs > MEDIUM_FUNCTION_COUNT_THRESHOLD:
            level = "aac"
            logger.info(f"Medium binary ({quick_funcs} functions). Using 'aac' analysis.")
            self.binary.analyze("aac")
        else:
            level = "aaa"
            logger.info(
                f"Small binary ({quick_funcs} functions). "
                f"Using full 'aaa' analysis (~{int(aa_time * 3)}s estimated)."
            )
            self.binary.analyze("aaa")

        return level

    def add_mutation(self, mutation: MutationPass) -> "MorphEngine":
        """
        Add a mutation pass to the pipeline.

        Automatically adjusts mutation parameters when in memory-efficient mode.

        Args:
            mutation: Mutation pass to add

        Returns:
            Self for method chaining
        """
        # Adjust mutation config for large binaries to prevent OOM
        if self._memory_efficient_mode:
            mutation_name = mutation.__class__.__name__
            if mutation_name == "NopInsertionPass":
                # Reduce NOPs per function from 5 to 2
                original = mutation.config.get("max_nops_per_function", 5)
                mutation.config["max_nops_per_function"] = min(2, original)
                mutation.max_nops = mutation.config["max_nops_per_function"]
                logger.debug(
                    f"Memory-efficient mode: reduced max_nops_per_function "
                    f"from {original} to {mutation.max_nops}"
                )
            elif mutation_name == "InstructionExpansionPass":
                # Reduce expansions if config exists
                if "max_expansions" in mutation.config:
                    original = mutation.config["max_expansions"]
                    mutation.config["max_expansions"] = min(2, original)
                    logger.debug(
                        f"Memory-efficient mode: reduced max_expansions "
                        f"from {original} to {mutation.config['max_expansions']}"
                    )

        self.pipeline.add_pass(mutation)
        logger.debug(f"Added mutation: {mutation.__class__.__name__}")
        return self

    def remove_mutation(self, mutation_name: str) -> "MorphEngine":
        """
        Remove a mutation pass from the pipeline by name.

        Args:
            mutation_name: Name of the mutation to remove

        Returns:
            Self for method chaining
        """
        self.pipeline.passes = [
            p
            for p in self.pipeline.passes
            if getattr(p, "name", p.__class__.__name__) != mutation_name
        ]
        logger.debug(f"Removed mutation: {mutation_name}")
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

        output_path = Path(output_path)

        logger.info(f"Saving transformed binary to: {output_path}")

        shutil.copy2(self.binary.path, output_path)
        logger.info(f"Binary successfully saved to: {output_path}")

        if platform.system() == "Darwin":
            entitlements = self.config.get("codesign_entitlements")
            if entitlements:
                entitlements = Path(entitlements)
            hardened = bool(self.config.get("codesign_hardened", False))
            timestamp = bool(self.config.get("codesign_timestamp", False))

            from r2morph.platform.macho_handler import MachOHandler

            handler = MachOHandler(output_path)
            if handler.is_macho():
                ok, msg = handler.validate_integrity()
                if not ok:
                    logger.warning(f"Mach-O layout check failed: {msg}")
                repaired = handler.repair_integrity(
                    entitlements=entitlements,
                    hardened=hardened,
                    timestamp=timestamp,
                )
                if not repaired:
                    logger.warning(f"Mach-O repair/signing failed for: {output_path}")
                try:
                    output_path.chmod(output_path.stat().st_mode | 0o111)
                except OSError as e:
                    logger.warning(f"Failed to mark Mach-O executable: {e}")
            else:
                signer = CodeSigner()
                if not signer.sign_binary(
                    output_path,
                    adhoc=True,
                    entitlements=entitlements,
                    hardened=hardened,
                    timestamp=timestamp,
                ):
                    logger.warning(f"Ad-hoc signing failed for: {output_path}")

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
