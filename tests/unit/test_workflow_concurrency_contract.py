from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def test_adversarial_workflow_preserves_active_campaigns() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "adversarial-benchmark.yml").read_text(encoding="utf-8")

    expect("group: adversarial-benchmark-${{ github.ref }}" in workflow and "cancel-in-progress: false" in workflow)


def test_ci_preserves_active_validation_after_evidence_pushes() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    expect("group: ${{ github.workflow }}-${{ github.ref }}" in workflow and "cancel-in-progress: false" in workflow)


def test_fuzz_workflow_preserves_active_campaigns() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "fuzz.yml").read_text(encoding="utf-8")

    expect("group: continuous-fuzz-${{ github.ref }}" in workflow and "cancel-in-progress: false" in workflow)
