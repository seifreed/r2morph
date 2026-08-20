"""Assertion helper used by tests that must remain valid under strict linting."""

from typing import Any


def expect(condition: bool, message: Any = None) -> None:
    """Raise the standard test failure when a condition is false."""
    if not condition:
        if message is None:
            raise AssertionError
        raise AssertionError(message)


def expect_all(*conditions: bool) -> None:
    """Check a compact group of independent contract conditions."""
    for condition in conditions:
        expect(condition)
