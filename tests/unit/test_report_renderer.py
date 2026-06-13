from io import StringIO

from rich.console import Console

from r2morph.reporting.report_renderer import ReportRenderer


def make_console() -> tuple[Console, StringIO]:
    stream = StringIO()
    return Console(file=stream, force_terminal=False, color_system=None, width=100), stream


def test_report_renderer_only_failed_gates_uses_gate_summary() -> None:
    console, stream = make_console()
    renderer = ReportRenderer(console)

    renderer.render_report(
        {
            "summary": {},
            "gate_failures": {"require_pass_severity_failure_count": 0},
            "gate_failure_priority": [],
            "mutations": [],
        },
        only_failed_gates=True,
    )

    assert "All gate checks passed" in stream.getvalue()


def test_report_renderer_only_mismatches_renders_symbolic_summary() -> None:
    console, stream = make_console()
    renderer = ReportRenderer(console)

    renderer.render_report(
        {
            "summary": {
                "symbolic_overview": {
                    "symbolic_requested": 1,
                    "observable_match": 0,
                    "observable_mismatch": 1,
                    "bounded_only": 0,
                    "without_coverage": 0,
                }
            },
            "mutations": [
                {
                    "pass_name": "demo-pass",
                    "start_address": 4096,
                    "end_address": 4112,
                    "metadata": {
                        "symbolic_observable_check_performed": True,
                        "symbolic_observable_equivalent": False,
                        "symbolic_observable_mismatches": ["eax", "flags"],
                    },
                }
            ],
        },
        only_mismatches=True,
    )

    output = stream.getvalue()
    assert "Symbolic Validation Summary" in output
    assert "Observable Mismatches by Pass" in output
