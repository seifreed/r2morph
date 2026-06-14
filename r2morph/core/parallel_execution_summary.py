"""Result summary helpers for parallel mutation execution."""

from __future__ import annotations

from typing import Any

from r2morph.core.parallel_planner import PassResult, PassStatus


def build_parallel_results_summary(results: dict[str, PassResult]) -> dict[str, Any]:
    """Build a human- and machine-readable summary of execution results."""
    completed = sum(1 for r in results.values() if r.status == PassStatus.COMPLETED)
    failed = sum(1 for r in results.values() if r.status == PassStatus.FAILED)
    skipped = sum(1 for r in results.values() if r.status == PassStatus.SKIPPED)
    rolled_back = sum(1 for r in results.values() if r.status == PassStatus.ROLLED_BACK)

    total_mutations = sum(r.mutations_applied for r in results.values())
    total_duration = sum(r.duration_seconds for r in results.values())

    return {
        "total_passes": len(results),
        "completed": completed,
        "failed": failed,
        "skipped": skipped,
        "rolled_back": rolled_back,
        "total_mutations": total_mutations,
        "total_duration_seconds": total_duration,
        "passes": {name: result.to_dict() for name, result in results.items()},
    }
