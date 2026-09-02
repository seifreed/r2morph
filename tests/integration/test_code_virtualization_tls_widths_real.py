"""Real Unicorn regression for byte and word TLS memory operations."""

from __future__ import annotations

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_tls_widths_x86_64"
_EXPECTED_EXIT_CODE = 42


def test_tls_byte_and_word_virtualization_preserves_exit_code(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated_tls_widths"
    shutil.copy(_FIXTURE, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        binary.analyze()
        tls_function = next(function for function in binary.get_functions() if "tls_widths" in function.get("name", ""))
        original_prefix = binary.read_bytes(int(tls_function["addr"]), 5)
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        mutated_prefix = binary.read_bytes(int(tls_function["addr"]), 5)
        binary.save()
    finally:
        binary.close()

    expect(
        stats["functions_virtualized"] >= 1
        and original_prefix != mutated_prefix
        and emulate_exit_code(_FIXTURE) == emulate_exit_code(mutated) == _EXPECTED_EXIT_CODE
    )
