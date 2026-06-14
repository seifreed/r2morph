from pathlib import Path

import r2morph.platform.macho_handler_repair as macho_repair


def test_validate_integrity_rejects_non_macho() -> None:
    handler = type("Handler", (), {"is_macho": lambda self: False})()

    ok, msg = macho_repair.validate_integrity(handler)

    assert ok is False
    assert msg == "Not a Mach-O binary"


def test_fix_load_commands_handles_missing_binary(monkeypatch) -> None:
    handler = type("Handler", (), {"_parse_lief": lambda self: None})()

    ok, fixes = macho_repair.fix_load_commands(handler)

    assert ok is True
    assert fixes == []


def test_full_repair_aggregates_results(monkeypatch) -> None:
    handler = type(
        "Handler",
        (),
        {
            "is_macho": lambda self: True,
            "binary_path": Path("test.macho"),
            "repair_integrity": lambda self, **kwargs: False,
        },
    )()

    monkeypatch.setattr(macho_repair, "fix_load_commands", lambda _handler: (True, ["load"]))
    monkeypatch.setattr(macho_repair, "fix_bind_symbols", lambda _handler: (False, ["bind"]))
    monkeypatch.setattr(macho_repair, "fix_segment_permissions", lambda _handler: (True, []))
    monkeypatch.setattr(
        macho_repair,
        "platform",
        type("P", (), {"system": staticmethod(lambda: "Linux")})(),
    )

    ok, repairs = macho_repair.full_repair(handler)

    assert ok is False
    assert "load" in repairs
    assert "bind" in repairs
    assert "Warning: bind_symbols repair may have issues" in repairs
