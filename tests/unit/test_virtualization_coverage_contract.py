"""Regression contract for the VM fixture coverage inventory."""

from pathlib import Path

from scripts.virtualization_coverage import _capabilities_for_fixture, build_coverage_inventory
from tests.utils.assertions import expect

_DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "dataset"
_MINIMUM_FIXTURE_COUNT = 80


def test_virtualization_coverage_inventory_covers_every_capability_family() -> None:
    report = build_coverage_inventory(_DATASET)

    expect(report["fixture_count"] >= _MINIMUM_FIXTURE_COUNT)
    expect(report["covered_capability_count"] == report["capability_count"])


def test_virtualization_coverage_inventory_classifies_every_vm_fixture() -> None:
    report = build_coverage_inventory(_DATASET)

    expect(report["unclassified"] == [])


def test_virtualization_coverage_classifies_syscall_outside_call_capability() -> None:
    expect(_capabilities_for_fixture("elf_vm_syscall_x86_64") == ("signals_and_system_calls",))
