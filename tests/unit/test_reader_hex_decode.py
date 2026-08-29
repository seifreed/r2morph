import pytest

from r2morph.core.reader import BinaryReader, _decode_hex_bytes
from tests._doubles.scripted_r2_binary import ScriptedR2Binary
from tests.utils.assertions import expect

_EXPECTED_FUNCTION_ADDRESS = 0x401000


class _FunctionListDisassembler:
    def cmdj(self, command: str) -> list[dict[str, int]]:
        if command == "aflj":
            return [{"offset": 0x401000}]
        return []


@pytest.mark.parametrize(
    ("hex_data", "expected_size", "expected"),
    [
        ("4142", 2, b"AB"),
        (" 4142\n", 2, b"AB"),
        ("", 0, b""),
        ("4g", 1, b""),
        ("41", 2, b""),
    ],
)
def test_decode_hex_bytes_input_returns_expected_bytes(
    hex_data: str,
    expected_size: int,
    expected: bytes,
) -> None:
    expect(_decode_hex_bytes(hex_data, 4096, expected_size) == expected)


def test_resolve_symbolic_vars_known_location_uses_disassembler_location() -> None:
    disassembler = ScriptedR2Binary({"afv @": "int var_10h @ rbp - 0x10"}).r2
    reader = BinaryReader(disassembler)

    expect(reader.resolve_symbolic_vars("mov eax, [var_10h]", 4096) == "mov eax, [rbp - 0x10]")


def test_resolve_symbolic_vars_base_pointer_variable_uses_fallback_location() -> None:
    disassembler = ScriptedR2Binary({}).r2
    reader = BinaryReader(disassembler)

    expect(reader.resolve_symbolic_vars("mov eax, [var_bp_20h]") == "mov eax, [rbp - 0x20]")


def test_get_functions_normalizes_offset_to_canonical_address() -> None:
    reader = BinaryReader(_FunctionListDisassembler())

    functions = reader.get_functions()

    expect(functions[0]["addr"] == _EXPECTED_FUNCTION_ADDRESS)


def test_get_functions_normalizes_cached_offset_to_canonical_address() -> None:
    reader = BinaryReader(_FunctionListDisassembler())

    functions = reader.get_functions(cached=[{"offset": _EXPECTED_FUNCTION_ADDRESS}])

    expect(functions[0]["addr"] == _EXPECTED_FUNCTION_ADDRESS)
