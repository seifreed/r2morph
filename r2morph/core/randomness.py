"""System randomness with reproducible explicitly seeded streams."""

from __future__ import annotations

import random as _stdlib_random
from collections.abc import MutableSequence, Sequence
from typing import Any

_Seed = int | float | str | bytes | bytearray | None
_RandomState = tuple[Any, ...]


class Random(_stdlib_random.Random):
    """Explicit deterministic stream preserving the stdlib seed contract."""

    pass


_source: list[_stdlib_random.Random] = [_stdlib_random.SystemRandom()]


def seed(a: _Seed = None, version: int = 2) -> None:
    """Select a reproducible stream, or system entropy when ``a`` is None."""
    del version
    _source[0] = _stdlib_random.SystemRandom() if a is None else Random(a)


def getstate() -> _RandomState | None:
    """Return the current deterministic stream state when one is selected."""
    if isinstance(_source[0], _stdlib_random.SystemRandom):
        return None
    return _source[0].getstate()


def setstate(state: _RandomState | None) -> None:
    """Restore a state returned by :func:`getstate`."""
    if state is None:
        _source[0] = _stdlib_random.SystemRandom()
        return
    if isinstance(_source[0], _stdlib_random.SystemRandom):
        _source[0] = Random()
    _source[0].setstate(state)


def choice[T](seq: Sequence[T]) -> T:
    return _source[0].choice(seq)


def choices[T](
    population: Sequence[T],
    weights: Sequence[float] | None = None,
    *,
    cum_weights: Sequence[float] | None = None,
    k: int = 1,
) -> list[T]:
    return _source[0].choices(population, weights=weights, cum_weights=cum_weights, k=k)


def randint(a: int, b: int) -> int:
    return _source[0].randint(a, b)


def randrange(start: int, stop: int | None = None, step: int = 1) -> int:
    return _source[0].randrange(start, stop, step)


def getrandbits(k: int) -> int:
    return _source[0].getrandbits(k)


def random() -> float:
    return _source[0].random()


def sample[T](population: Sequence[T], k: int, *, counts: Sequence[int] | None = None) -> list[T]:
    return _source[0].sample(population, k, counts=counts)


def shuffle[T](values: MutableSequence[T]) -> None:
    _source[0].shuffle(values)
