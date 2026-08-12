import r2morph.platform.macho_handler_repair as macho_repair
from r2morph.platform.repair_aggregation import aggregate_repair_results


def test_validate_integrity_rejects_non_macho() -> None:
    handler = type("Handler", (), {"is_macho": lambda self: False})()

    ok, msg = macho_repair.validate_integrity(handler)

    assert ok is False
    assert msg == "Not a Mach-O binary"


def test_fix_load_commands_handles_missing_binary() -> None:
    handler = type("Handler", (), {"_parse_lief": lambda self: None})()

    ok, fixes = macho_repair.fix_load_commands(handler)

    assert ok is True
    assert fixes == []


def test_repair_aggregation_reports_failed_macho_check() -> None:
    ok, repairs = aggregate_repair_results([("load_commands", (True, ["load"])), ("bind_symbols", (False, ["bind"]))])

    assert ok is False and repairs == ["load", "bind", "Warning: bind_symbols repair may have issues"]
