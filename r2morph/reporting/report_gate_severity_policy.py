"""Pure severity policy helpers for reporting gates."""

from __future__ import annotations

from r2morph.core.constants import SEVERITY_ORDER


def _severity_threshold_met(
    severity_rows: list[dict[str, object]],
    min_severity_rank: int | None,
) -> bool:
    """Return True when at least one severity row meets the requested threshold."""
    if min_severity_rank is None:
        return True
    if not severity_rows:
        return False
    return any(
        SEVERITY_ORDER.get(str(row.get("severity", "not-requested")), 99) <= min_severity_rank for row in severity_rows
    )


def _pass_severity_requirements_met(
    severity_rows: list[dict[str, object]],
    requirements: list[tuple[str, str, int]],
) -> tuple[bool, list[str]]:
    """Check whether all required passes meet their minimum allowed severity rank."""
    if not requirements:
        return True, []
    by_pass = {str(row.get("pass_name", "")): row for row in severity_rows}
    failures: list[str] = []
    for pass_name, severity, rank in requirements:
        row = by_pass.get(pass_name)
        if row is None:
            failures.append(f"{pass_name}=missing(expected <= {severity})")
            continue
        actual = str(row.get("severity", "not-requested"))
        actual_rank = SEVERITY_ORDER.get(actual, 99)
        if actual_rank > rank:
            failures.append(f"{pass_name}={actual}(expected <= {severity})")
    return not failures, failures
