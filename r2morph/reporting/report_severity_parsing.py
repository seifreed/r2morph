"""Pure severity parsing helpers for reporting gates."""

from __future__ import annotations

import re

from r2morph.core.constants import SEVERITY_ORDER, UNKNOWN_SEVERITY_RANK

_EXPECTED_SEVERITY_PATTERN = re.compile(r"expected <= ([^)]+)")


def _expected_severity_from_failure(failure: str) -> str | None:
    """Extract the expected-severity label from a gate failure string."""
    match = _EXPECTED_SEVERITY_PATTERN.search(failure)
    return match.group(1) if match else None


def _expected_severity_rank_from_failure(failure: str) -> int:
    """Map a gate failure string to a severity rank."""
    severity = _expected_severity_from_failure(failure)
    if severity is None:
        return UNKNOWN_SEVERITY_RANK
    return SEVERITY_ORDER.get(severity, UNKNOWN_SEVERITY_RANK)
