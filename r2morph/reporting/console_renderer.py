"""Backward-compatibility shim -- all functions moved to report_rendering.py.

Lazy re-export to avoid circular imports at module load time.
"""


def __getattr__(name: str):
    """Lazily import symbols from report_rendering on first access."""
    from r2morph.reporting import report_rendering as _rr

    _exports = {
        "CONSOLE",
        "create_table",
        "render_pass_capabilities",
        "render_pass_validation_contexts",
        "render_symbolic_sections",
        "render_gate_sections",
        "render_degradation_sections",
        "render_only_mismatches_sections",
        "render_only_pass_sections",
        "render_report_filter_messages",
        "render_summary_table",
        "render_gate_evaluation_sections",
        "render_general_report_sections",
        "render_general_only_pass_sections",
        "render_mismatch_summary_sections",
        "render_validation_context_table",
    }
    if name in _exports:
        return getattr(_rr, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
