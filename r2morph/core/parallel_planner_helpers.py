"""Pure helper functions for parallel pass planning."""

from __future__ import annotations

from typing import Any

from r2morph.protocols import MutationPassProtocol


def _dependency_lists(dependencies: dict[str, Any], pass_name: str) -> tuple[list[str], list[str]]:
    """Return normalized dependency lists for a pass name."""
    dep = dependencies.get(pass_name)
    if dep is None:
        return [], []

    return list(dep.requires), list(dep.conflicts)


def build_execution_stages(
    passes: list[MutationPassProtocol],
    dependencies: dict[str, Any],
) -> list[list[str]]:
    """Build dependency-safe execution stages for a pass list."""
    pass_names = [p.name for p in passes]
    pass_name_set = set(pass_names)
    stages: list[list[str]] = []
    scheduled: set[str] = set()

    while len(scheduled) < len(pass_name_set):
        stage: list[str] = []

        for pass_name in pass_names:
            if pass_name in scheduled:
                continue

            requires, conflicts = _dependency_lists(dependencies, pass_name)
            if any(req not in scheduled for req in requires):
                continue
            if any(conflict in scheduled for conflict in conflicts):
                continue

            stage.append(pass_name)

        if not stage:
            remaining = [pass_name for pass_name in pass_names if pass_name not in scheduled]
            stage = list(remaining)

        scheduled.update(stage)
        stages.append(stage)

    return stages


def build_conflict_pairs(
    passes: list[MutationPassProtocol],
    dependencies: dict[str, Any],
) -> list[tuple[str, str]]:
    """Build the pairwise pass conflict list."""
    conflicts: list[tuple[str, str]] = []
    pass_names = [p.name for p in passes]

    for i, name1 in enumerate(pass_names):
        for name2 in pass_names[i + 1 :]:
            _, conflicts1 = _dependency_lists(dependencies, name1)
            _, conflicts2 = _dependency_lists(dependencies, name2)

            if name2 in conflicts1 or name1 in conflicts2:
                conflicts.append((name1, name2))

    return conflicts
