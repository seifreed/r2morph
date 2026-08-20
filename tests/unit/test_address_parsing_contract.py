from r2morph.validation.address_parsing import parse_address
from tests.utils.assertions import expect

_EXPECTED_PARSE_ADDRESS_0X10_16 = 16
_EXPECTED_PARSE_ADDRESS_12_12 = 12
_EXPECTED_PARSE_ADDRESS_12_12_2 = 12


def test_address_parsing_contract() -> None:
    expect(parse_address(None) == 0)
    expect(parse_address(12) == _EXPECTED_PARSE_ADDRESS_12_12)
    expect(parse_address("0x10") == _EXPECTED_PARSE_ADDRESS_0X10_16)
    expect(parse_address("12") == _EXPECTED_PARSE_ADDRESS_12_12_2)
