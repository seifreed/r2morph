import shutil
from pathlib import Path

import r2morph.platform.pe_handler_repair as pe_repair
from r2morph.platform.pe_handler_parsing import calculate_pe_checksum, get_checksum_offset
from r2morph.platform.repair_aggregation import aggregate_repair_results

_PE_FIXTURE = Path(__file__).parents[2] / "fixtures" / "dataset" / "pe_x86_64.exe"


def test_fix_checksum_writes_expected_value(tmp_path) -> None:
    binary_path = tmp_path / "test.exe"
    shutil.copy2(_PE_FIXTURE, binary_path)
    expected = calculate_pe_checksum(binary_path)
    checksum_offset = get_checksum_offset(binary_path)

    handler = type("Handler", (), {"binary_path": binary_path})()

    assert pe_repair.fix_checksum(handler) is True
    assert checksum_offset is not None
    assert int.from_bytes(binary_path.read_bytes()[checksum_offset : checksum_offset + 4], "little") == expected


def test_validate_integrity_rejects_non_pe() -> None:
    handler = type(
        "Handler",
        (),
        {
            "binary_path": Path("test.exe"),
            "is_pe": lambda self: False,
        },
    )()

    valid, issues = pe_repair.validate_integrity(handler)
    assert valid is False
    assert issues == ["Not a PE binary"]


def test_repair_aggregation_collects_failures_and_messages() -> None:
    success, repairs = aggregate_repair_results(
        [("imports", (True, ["imports"])), ("exports", (False, ["exports"])), ("headers", True)]
    )

    assert success is False and repairs == ["imports", "exports", "Warning: exports repair may have issues"]
