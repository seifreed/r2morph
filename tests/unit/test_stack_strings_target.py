"""Target-normalization contracts for stack-string rewriting."""

from __future__ import annotations

from typing import Any

from r2morph.mutations.stack_strings import StackStringsPass
from tests.utils.assertions import expect

_BITS_64 = 64


class _ArchitectureBinary:
    """Small explicit binary double for target metadata only."""

    def __init__(self, binary_format: str, architecture: str, bits: int) -> None:
        self._arch_info = {"format": binary_format, "arch": architecture, "bits": bits}

    def get_arch_info(self) -> dict[str, Any]:
        return self._arch_info


def test_stack_strings_accepts_hyphenated_x86_64_elf_metadata() -> None:
    binary = _ArchitectureBinary("ELF", "x86-64", _BITS_64)

    expect(StackStringsPass._supports_apply_target(binary))


def test_stack_strings_accepts_radare2_x86_64_elf_metadata() -> None:
    binary = _ArchitectureBinary("ELF", "x86", _BITS_64)

    expect(StackStringsPass._supports_apply_target(binary))


def test_stack_strings_rejects_non_elf_target_metadata() -> None:
    binary = _ArchitectureBinary("PE", "x86-64", _BITS_64)

    expect(not StackStringsPass._supports_apply_target(binary))
