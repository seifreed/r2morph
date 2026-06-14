"""Pure severity parsing helpers for reporting gates."""

from __future__ import annotations

import re

from r2morph.core.constants import SEVERITY_ORDER


def _expected_severity_rank_from_failure(failure: str) -> int:
    """Map a gate failure string to a severity rank."""
    match = re.search(r"expected <= ([^)]+)", failure)
    if match:
        return SEVERITY_ORDER.get(match.group(1), 99)
    return 99
