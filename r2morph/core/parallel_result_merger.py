"""Result merging helpers for parallel mutation execution."""

from __future__ import annotations

from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.parallel_executor_models import MutationResult, ResolutionStrategy
from r2morph.core.parallel_result_merger_helpers import (
    build_conflict_resolutions,
    collect_conflict_regions,
    detect_conflicts_from_regions,
    summarize_results,
)


class ResultMerger:
    """Merges mutation results from parallel execution."""

    def __init__(self) -> None:
        self._results: list[MutationResult] = []
        self._conflicts: list[dict[str, Any]] = []

    def add_result(self, result: MutationResult) -> None:
        """Add a mutation result."""
        self._results.append(result)

    def merge(self, binary: Binary | None, results: list[MutationResult] | None = None) -> dict[str, Any]:
        """Merge mutation results."""
        results = results or self._results
        return summarize_results(results, self._conflicts)

    def detect_conflicts(self, results: list[MutationResult]) -> list[dict[str, Any]]:
        """Detect conflicts between mutation results."""
        regions_by_func = collect_conflict_regions(results)
        conflicts = detect_conflicts_from_regions(regions_by_func)

        self._conflicts = conflicts
        return conflicts

    def resolve_conflicts(
        self,
        conflicts: list[dict[str, Any]],
        strategy: ResolutionStrategy = ResolutionStrategy.SKIP,
    ) -> list[dict[str, Any]]:
        """Generate resolutions for conflicts."""
        return build_conflict_resolutions(conflicts, strategy)

    def clear(self) -> None:
        """Clear stored results."""
        self._results.clear()
        self._conflicts.clear()
