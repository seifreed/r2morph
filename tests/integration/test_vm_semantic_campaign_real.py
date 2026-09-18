from pathlib import Path

from scripts.vm_semantic_campaign import _load_coverage, merge_campaign_reports, run_campaign
from tests.utils.assertions import expect

_MERGED_SEED_COUNT = 2
_MERGED_FIXTURE_COUNT = 2


def test_vm_semantic_campaign_fixture_virtualizes_with_native_parity() -> None:
    report = run_campaign(
        Path("fixtures/dataset"),
        _load_coverage(Path("docs/virtualization-coverage.json")),
        seed=20260916,
        fixture_names=("elf_vm_shift_x86_64",),
    )

    fixture_categories = {
        category
        for category, fixture_names in _load_coverage(Path("docs/virtualization-coverage.json")).items()
        if "elf_vm_shift_x86_64" in fixture_names
    }
    expect(
        report["status"] == "passed"
        and report["passed_count"] == 1
        and all(
            report["category_summary"][category]["passed_count"]
            == report["category_summary"][category]["fixture_count"]
            and report["category_summary"][category]["failed_count"] == 0
            for category in fixture_categories
        )
    )


def test_vm_semantic_campaign_merges_multiple_seed_runs_without_failures() -> None:
    coverage = _load_coverage(Path("docs/virtualization-coverage.json"))
    reports = tuple(
        run_campaign(
            Path("fixtures/dataset"),
            coverage,
            seed=seed,
            fixture_names=("elf_vm_shift_x86_64",),
        )
        for seed in (20260916, 20260917)
    )
    merged = merge_campaign_reports(reports)

    expect(
        merged["status"] == "passed"
        and merged["seed_count"] == _MERGED_SEED_COUNT
        and merged["fixture_count"] == _MERGED_FIXTURE_COUNT
        and merged["passed_count"] == _MERGED_FIXTURE_COUNT
        and merged["failed_count"] == 0
        and not merged["failures"]
    )
