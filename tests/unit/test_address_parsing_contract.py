from r2morph.validation.address_parsing import parse_address


def test_address_parsing_contract() -> None:
    assert parse_address(None) == 0
    assert parse_address(12) == 12
    assert parse_address("0x10") == 16
    assert parse_address("12") == 12
