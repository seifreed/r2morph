"""Pure normalization helpers for report pass filter views."""

from __future__ import annotations

from typing import Any


def _normalize_pass_filter_views(general_renderer_state: dict[str, Any]) -> dict[str, list[str]]:
    """Normalize renderer filter-view keys into persisted report filter keys."""

    def _remap_key(key: str) -> str:
        if key in {"risky", "clean", "covered", "uncovered"}:
            return f"only_{key}_passes"
        if key == "structural_risk":
            return "only_structural_risk"
        if key == "symbolic_risk":
            return "only_symbolic_risk"
        return key

    if general_renderer_state.get("general_filter_views"):
        source = dict(general_renderer_state.get("general_filter_views", {}) or {})
    elif general_renderer_state.get("filter_views"):
        source = dict(general_renderer_state.get("filter_views", {}) or {})
    else:
        return {}

    return {_remap_key(key): value for key, value in source.items()}
