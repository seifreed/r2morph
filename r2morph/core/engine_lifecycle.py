"""Lifecycle helpers extracted from MorphEngine."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import time
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
from r2morph.session import MorphSession

logger = logging.getLogger(__name__)


def should_use_low_memory(path: Path) -> bool:
    """Determine if low-memory mode should be enabled based on file size."""
    binary_size_mb = os.path.getsize(path) / (1024 * 1024)
    return binary_size_mb > LARGE_BINARY_THRESHOLD_MB


def create_working_copy(original_path: Path) -> Path:
    """Create a temporary working copy of the binary."""
    temp_dir = Path(tempfile.gettempdir()) / "r2morph"
    temp_dir.mkdir(exist_ok=True)
    working_copy = temp_dir / f"{original_path.name}.working"
    shutil.copy2(original_path, working_copy)
    return working_copy


def get_binary_size_mb(path: Path) -> float:
    """Get binary file size in megabytes."""
    return os.path.getsize(path) / (1024 * 1024)


def should_enable_memory_efficient_mode(binary_size_mb: float, function_count: int) -> bool:
    """Determine if memory-efficient mode should be enabled."""
    return binary_size_mb > LARGE_BINARY_THRESHOLD_MB or function_count > LARGE_FUNCTION_COUNT_THRESHOLD


def load_binary(
    engine: Any,
    path: str | Path,
    writable: bool = True,
) -> Any:
    """Load a binary for transformation using the engine state."""
    path = Path(path)
    logger.info(f"Loading binary: {path}")

    if writable:
        engine._session = MorphSession()
        working_copy = engine._session.start(path)
        logger.debug(f"Created session working copy: {working_copy}")
        engine._original_path = path
        target_path = working_copy
    else:
        engine._original_path = None
        target_path = path

    low_memory = should_use_low_memory(target_path)
    engine.binary = Binary(target_path, writable=writable, low_memory=low_memory)
    engine.binary.open()
    return engine


def auto_detect_analysis_level(engine: Any) -> str:
    """Auto-detect optimal analysis level based on binary complexity."""
    logger.info("Running quick analysis to estimate complexity...")
    start = time.time()
    assert engine.binary is not None
    engine.binary.analyze("aa")
    quick_funcs = len(engine.binary.get_functions())
    aa_time = time.time() - start

    binary_size_mb = get_binary_size_mb(engine.binary.path)
    avg_func_size = (binary_size_mb * 1024 * 1024) / quick_funcs if quick_funcs > 0 else 0

    logger.info(
        f"Binary stats: {quick_funcs} functions, {binary_size_mb:.1f} MB, "
        f"avg {avg_func_size:.0f} bytes/func (aa took {aa_time:.1f}s)"
    )

    if quick_funcs > VERY_MANY_FUNCTIONS_THRESHOLD:
        level = "aa"
        logger.warning(
            f"Very large binary ({quick_funcs} functions). Using fast analysis level 'aa' (already complete)."
        )
    elif quick_funcs > MANY_FUNCTIONS_THRESHOLD:
        level = "aac"
        logger.warning(
            f"Large binary ({quick_funcs} functions). Using 'aac' analysis (adds ~10-20s for call analysis)."
        )
        assert engine.binary is not None
        engine.binary.analyze("aac")
    elif quick_funcs > MEDIUM_FUNCTION_COUNT_THRESHOLD:
        level = "aac"
        logger.info(f"Medium binary ({quick_funcs} functions). Using 'aac' analysis.")
        assert engine.binary is not None
        engine.binary.analyze("aac")
    else:
        level = "aaa"
        logger.info(
            f"Small binary ({quick_funcs} functions). Using full 'aaa' analysis (~{int(aa_time * 3)}s estimated)."
        )
        assert engine.binary is not None
        engine.binary.analyze("aaa")

    return level


def analyze(engine: Any, level: str = "auto") -> Any:
    """Analyze the loaded binary using the engine state."""
    if not engine.binary:
        raise RuntimeError("No binary loaded. Call load_binary() first.")

    if level == "auto":
        level = auto_detect_analysis_level(engine)
    else:
        logger.info(f"Analyzing binary with level: {level}...")
        assert engine.binary is not None
        engine.binary.analyze(level)

    functions = engine.binary.get_functions()
    arch_info = engine.binary.get_arch_info()

    engine._stats = {
        "functions": len(functions),
        "arch": arch_info.get("arch"),
        "bits": arch_info.get("bits"),
        "format": arch_info.get("format"),
    }

    logger.info(f"Analysis complete. Found {len(functions)} functions")
    logger.debug(f"Architecture: {arch_info}")

    assert engine.binary is not None
    binary_size_mb = get_binary_size_mb(engine.binary.path)
    if should_enable_memory_efficient_mode(binary_size_mb, len(functions)):
        engine._memory_efficient_mode = True
        logger.warning(
            f"Large binary detected ({binary_size_mb:.1f} MB, {len(functions)} functions). "
            f"Enabling memory-efficient mode to prevent OOM crashes."
        )
        logger.info(
            f"Memory-efficient mode: reduced mutations per function, "
            f"batch processing with r2 restarts every {BATCH_MUTATION_CHECKPOINT} mutations."
        )

    return engine
