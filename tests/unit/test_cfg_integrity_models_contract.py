"""Contract tests for CFG integrity models."""

from __future__ import annotations

from r2morph.validation.cfg_integrity_models import (
    CFGSnapshot,
    IntegrityCheck,
    IntegrityReport,
    IntegrityStatus,
    IntegrityViolation,
)
from tests.utils.assertions import expect

_EXPECTED_SNAPSHOT_FUNCTION_ADDRESS_4096 = 0x1000


def test_integrity_status_values() -> None:
    expect(IntegrityStatus.VALID.value == "valid")
    expect(IntegrityStatus.PLT_THUNK.value == "plt_thunk")


def test_integrity_violation_serialization() -> None:
    violation = IntegrityViolation(
        status=IntegrityStatus.BROKEN_EDGE,
        address=0x1000,
        description="broken edge",
        metadata={"edge_type": "exception"},
    )

    expect(violation.to_dict()["status"] == "broken_edge")


def test_integrity_report_and_snapshot() -> None:
    snapshot = CFGSnapshot(function_address=0x1000, blocks={}, edges=[])
    report = IntegrityReport(
        valid=True,
        checks_run=[IntegrityCheck(name="reachability", description="test")],
    )

    expect(snapshot.function_address == _EXPECTED_SNAPSHOT_FUNCTION_ADDRESS_4096)
    expect(not (report.to_dict()["valid"] is not True))
