from pathlib import Path

import r2morph.platform.pe_handler_repair as pe_repair


def test_fix_checksum_writes_expected_value(tmp_path, monkeypatch) -> None:
    binary_path = tmp_path / "test.exe"
    binary_path.write_bytes(b"MZ" + b"\x00" * 128)

    monkeypatch.setattr(pe_repair, "calculate_pe_checksum", lambda path: 0x11223344)
    monkeypatch.setattr(pe_repair, "get_checksum_offset", lambda path: 8)

    handler = type("Handler", (), {"binary_path": binary_path})()

    assert pe_repair.fix_checksum(handler) is True
    assert binary_path.read_bytes()[8:12] == b"\x44\x33\x22\x11"


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


def test_full_repair_aggregates_results(monkeypatch) -> None:
    handler = object()

    monkeypatch.setattr(pe_repair, "fix_checksum", lambda _handler: True)
    monkeypatch.setattr(pe_repair, "fix_imports", lambda _handler: (True, ["imports"]))
    monkeypatch.setattr(pe_repair, "fix_exports", lambda _handler: (False, ["exports"]))
    monkeypatch.setattr(pe_repair, "fix_resources", lambda _handler: (True, []))
    monkeypatch.setattr(pe_repair, "refresh_headers", lambda _handler: True)

    success, repairs = pe_repair.full_repair(handler)

    assert success is False
    assert "imports" in repairs
    assert "exports" in repairs
    assert "Headers refreshed" in repairs
    assert "Warning: exports repair may have issues" in repairs
