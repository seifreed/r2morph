"""Pure row builders for text-oriented report rendering."""

from __future__ import annotations


def build_mismatch_summary_rows(
    mismatch_counts_by_pass: dict[str, int],
    mismatch_observables_by_pass: dict[str, list[str]],
) -> list[dict[str, str]]:
    """Build sorted mismatch-summary rows for table rendering."""
    rows: list[dict[str, str]] = []
    for pass_name, count in sorted(mismatch_counts_by_pass.items(), key=lambda item: -item[1]):
        observables = list(mismatch_observables_by_pass.get(pass_name, []) or [])[:3]
        obs_str = ", ".join(observables)
        if len(mismatch_observables_by_pass.get(pass_name, [])) > 3:
            obs_str += "..."
        rows.append(
            {
                "pass_name": pass_name,
                "count": str(count),
                "observables": obs_str,
            }
        )
    return rows
