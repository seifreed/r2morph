"""Baseline persistence for performance regression snapshots."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from r2morph.validation.performance_regression_models import PerformanceSnapshot

logger = logging.getLogger(__name__)


def save_baseline_snapshot(
    *,
    snapshot: PerformanceSnapshot,
    baseline_dir: Path,
    baseline_name: str,
) -> Path:
    """Persist a benchmark snapshot to the named baseline file."""
    baseline_file = baseline_dir / f"{baseline_name}.json"

    with open(baseline_file, "w") as f:
        json.dump(snapshot.to_dict(), f, indent=2)

    logger.info("Saved performance baseline: %s", baseline_file)
    return baseline_file


def load_baseline_snapshot(
    *,
    baseline_dir: Path,
    baseline_name: str,
) -> PerformanceSnapshot | None:
    """Load a benchmark snapshot from disk if it exists."""
    baseline_file = baseline_dir / f"{baseline_name}.json"

    if not baseline_file.exists():
        logger.warning("Baseline not found: %s", baseline_file)
        return None

    with open(baseline_file) as f:
        data = json.load(f)

    return PerformanceSnapshot(
        commit_hash=data["commit_hash"],
        timestamp=data["timestamp"],
        metrics=data["metrics"],
        environment=data["environment"],
        metadata=data.get("metadata", {}),
    )
