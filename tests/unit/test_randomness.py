"""Regression tests for the project randomness provider."""

from r2morph.core.randomness import Random


def test_random_same_seed_reproduces_stream() -> None:
    first = Random(1234)
    second = Random(1234)

    assert [first.getrandbits(64) for _ in range(4)] == [second.getrandbits(64) for _ in range(4)]
