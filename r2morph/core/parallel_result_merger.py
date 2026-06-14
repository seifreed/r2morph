"""Result merging helpers for parallel mutation execution."""

from __future__ import annotations

from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.parallel_executor_models import MutationResult, ResolutionStrategy


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

        merged = {
            "total_functions": len(results),
            "successful": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success),
            "total_mutations": sum(len(r.mutations_applied) for r in results),
            "total_bytes_modified": sum(r.bytes_modified for r in results),
            "total_time": sum(r.execution_time for r in results),
            "results": [r.to_dict() for r in results],
            "conflicts": self._conflicts,
        }

        return merged

    def detect_conflicts(self, results: list[MutationResult]) -> list[dict[str, Any]]:
        """Detect conflicts between mutation results."""
        conflicts = []
        regions_by_func: dict[int, list[dict]] = {}

        for result in results:
            if not result.success:
                continue

            for mutation in result.mutations_applied:
                addr = mutation.get("address", 0)
                size = mutation.get("size", 0)

                if result.function_address not in regions_by_func:
                    regions_by_func[result.function_address] = []

                regions_by_func[result.function_address].append(
                    {
                        "start": addr,
                        "end": addr + size,
                        "mutation": mutation,
                        "task_id": result.task_id,
                    }
                )

        for func_addr, regions in regions_by_func.items():
            for i, r1 in enumerate(regions):
                for r2 in regions[i + 1 :]:
                    if r1["start"] < r2["end"] and r2["start"] < r1["end"]:
                        conflicts.append(
                            {
                                "function": f"0x{func_addr:x}",
                                "region1": (r1["start"], r1["end"]),
                                "region2": (r2["start"], r2["end"]),
                                "task_ids": [r1["task_id"], r2["task_id"]],
                            }
                        )

        self._conflicts = conflicts
        return conflicts

    def resolve_conflicts(
        self,
        conflicts: list[dict[str, Any]],
        strategy: ResolutionStrategy = ResolutionStrategy.SKIP,
    ) -> list[dict[str, Any]]:
        """Generate resolutions for conflicts."""
        resolutions = []

        for conflict in conflicts:
            resolution = {
                "conflict": conflict,
                "strategy": strategy.value,
                "description": "",
            }

            if strategy == ResolutionStrategy.SKIP:
                resolution["description"] = f"Skip conflicting mutation in {conflict['function']}"
                resolution["action"] = "skip_second"

            elif strategy == ResolutionStrategy.REORDER:
                resolution["description"] = "Reorder mutations to avoid overlap"
                resolution["action"] = "reorder"

            elif strategy == ResolutionStrategy.MERGE:
                resolution["description"] = "Merge mutations into single pass"
                resolution["action"] = "merge"

            else:
                resolution["description"] = "Abort due to unresolvable conflict"
                resolution["action"] = "abort"

            resolutions.append(resolution)

        return resolutions

    def clear(self) -> None:
        """Clear stored results."""
        self._results.clear()
        self._conflicts.clear()
