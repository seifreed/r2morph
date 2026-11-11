"""Workflow contracts for reproducible differential evidence."""

from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_REQUIRED_WHEEL_GATED_SMOKES = (
    "Run cross-format differential smoke",
    "Run composition regression smoke",
    "Run VM semantic regression smoke",
    "Run parser and rewriter fuzz smoke",
    "Run extended maturity pass smoke",
)


def _workflow_step(workflow: str, name: str) -> str:
    start = workflow.index(f"      - name: {name}\n")
    following_step = workflow.find("\n      - name:", start + 1)
    return workflow[start:] if following_step < 0 else workflow[start:following_step]


def test_differential_smokes_require_successful_wheel_installation() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "differential-corpus.yml").read_text(encoding="utf-8")
    wheel_build = _workflow_step(workflow, "Build and install package wheel")
    smoke_steps = tuple(_workflow_step(workflow, name) for name in _REQUIRED_WHEEL_GATED_SMOKES)
    required_condition = "steps.build_wheel.outcome == 'success'"

    expect("id: build_wheel" in wheel_build and all(required_condition in step for step in smoke_steps))
