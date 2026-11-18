"""Fixture selection helpers for reproducible maturity campaigns."""

from pathlib import Path


def select_fixture_shard(fixtures: list[Path], index: int, count: int) -> list[Path]:
    """Select a stable count-balanced partition independent of binary sizes."""
    if count < 1:
        raise ValueError("fixture shard count must be positive")
    if index < 0 or index >= count:
        raise ValueError("fixture shard index must be within the shard count")
    ordered_fixtures = sorted(fixtures, key=lambda fixture: fixture.name)
    if len({fixture.name for fixture in ordered_fixtures}) != len(ordered_fixtures):
        raise ValueError("fixture shard selection requires unique fixture names")

    # shortcut: count-balanced shards can have runtime skew; revisit after measured shard timings show imbalance.
    return ordered_fixtures[index::count]
