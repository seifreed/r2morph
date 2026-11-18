"""Regression tests for reproducible corpus fixture shards."""

from pathlib import Path

import pytest

from scripts.protection_maturity_baseline import _select_fixture_shard
from tests.utils.assertions import expect


def test_fixture_shard_assignment_is_stable_when_compiled_sizes_vary(tmp_path: Path) -> None:
    size_sets = (
        (100, 90, 80, 70, 60, 50, 40, 30),
        (100, 30, 80, 50, 60, 90, 40, 70),
    )
    assignments = []

    for set_index, sizes in enumerate(size_sets):
        directory = tmp_path / str(set_index)
        directory.mkdir()
        fixtures = []
        for index, size in enumerate(sizes):
            fixture = directory / f"fixture-{index}"
            fixture.write_bytes(b"x" * size)
            fixtures.append(fixture)
        assignments.append(
            {
                fixture.name: shard_index
                for shard_index in range(2)
                for fixture in _select_fixture_shard(fixtures, shard_index, 2)
            }
        )
        if set_index:
            fixtures.reverse()

    expect(assignments[0] == assignments[1])


def test_fixture_shard_selection_balances_fixture_counts(tmp_path: Path) -> None:
    fixtures = []
    for index, size in enumerate((100, 90, 80, 70)):
        fixture = tmp_path / f"fixture-{index}"
        fixture.write_bytes(b"x" * size)
        fixtures.append(fixture)

    shards = [_select_fixture_shard(fixtures, index, 2) for index in range(2)]

    expect(
        [len(shard) for shard in shards] == [2, 2]
        and sorted(path for shard in shards for path in shard) == sorted(fixtures)
    )


def test_fixture_shard_selection_rejects_duplicate_fixture_names(tmp_path: Path) -> None:
    first = tmp_path / "first" / "sample"
    second = tmp_path / "second" / "sample"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_bytes(b"first")
    second.write_bytes(b"second")

    with pytest.raises(ValueError, match="unique fixture names"):
        _select_fixture_shard([first, second], 0, 2)
