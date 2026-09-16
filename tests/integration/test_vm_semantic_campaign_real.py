from pathlib import Path

from scripts.vm_semantic_campaign import _load_coverage, run_campaign
from tests.utils.assertions import expect


def test_vm_semantic_campaign_fixture_virtualizes_with_native_parity() -> None:
    report = run_campaign(
        Path("fixtures/dataset"),
        _load_coverage(Path("docs/virtualization-coverage.json")),
        seed=20260916,
        fixture_names=("elf_vm_shift_x86_64",),
    )

    expect(report["status"] == "passed" and report["passed_count"] == 1)
