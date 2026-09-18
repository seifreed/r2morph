"""Target-normalization contracts for stack-string rewriting."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.stack_strings import StackStringsPass, _direct_call_target, _parse_string_argument
from tests.utils.assertions import expect

_BITS_64 = 64
_SECTION_ADDRESS = 0x402000
_TAIL_TARGET = 0x401120
_STRING_DATA = b"stack-string"
_SECTION_BYTES = b"\x00" + _STRING_DATA + b"\x00"


class _ArchitectureBinary:
    """Small explicit binary double for target metadata only."""

    def __init__(self, binary_format: str, architecture: str, bits: int) -> None:
        self._arch_info = {"format": binary_format, "arch": architecture, "bits": bits}

    def get_arch_info(self) -> dict[str, Any]:
        return self._arch_info


class _SectionBinary:
    """Explicit binary double for the section-address contract."""

    def read_bytes(self, address: int, size: int) -> bytes:
        expect(address == _SECTION_ADDRESS and size == len(_SECTION_BYTES))
        return _SECTION_BYTES


def test_stack_strings_accepts_hyphenated_x86_64_elf_metadata() -> None:
    binary = _ArchitectureBinary("ELF", "x86-64", _BITS_64)

    expect(StackStringsPass._supports_apply_target(binary))


def test_stack_strings_accepts_radare2_x86_64_elf_metadata() -> None:
    binary = _ArchitectureBinary("ELF", "x86", _BITS_64)

    expect(StackStringsPass._supports_apply_target(binary))


def test_stack_strings_rejects_non_elf_target_metadata() -> None:
    binary = _ArchitectureBinary("PE", "x86-64", _BITS_64)

    expect(not StackStringsPass._supports_apply_target(binary))


def test_stack_strings_discovers_r2_vaddr_section() -> None:
    strings = StackStringsPass(config={"min_length": 4})._find_strings_in_section(
        _SectionBinary(),
        {"name": ".rodata", "vaddr": _SECTION_ADDRESS, "size": len(_SECTION_BYTES)},
    )

    expect(bool(strings) and strings[0]["address"] == _SECTION_ADDRESS + 1 and strings[0]["data"] == _STRING_DATA)


def test_stack_strings_parses_compiler_static_argument() -> None:
    parsed = _parse_string_argument({"opcode": "mov edi, str.stack_string_native"})

    expect(parsed == ("rdi", "mov edi, str.stack_string_native"))


def test_stack_strings_accepts_direct_tail_jump_target() -> None:
    expect(_direct_call_target({"type": "jmp", "jump": _TAIL_TARGET}) == _TAIL_TARGET)
