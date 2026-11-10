"""Regression coverage for the verified target boundary of block reordering."""

import logging
import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.block_reordering import BlockReorderingPass
from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_PE_FIXTURE = _ROOT / "fixtures" / "dataset" / "pe_mutation_x86_64.exe"


def test_block_reordering_marks_macho_x86_64_as_experimental() -> None:
    support = BlockReorderingPass().get_support()

    expect(
        support.formats == ("ELF", "Mach-O")
        and support.architectures == ("x86_64",)
        and support.stability == "stable"
        and support.notes
        == (
            "ELF x86-32 remains preview pending broader native corpus evidence.",
            "Mach-O x86_64 remains preview pending broader native corpus evidence.",
        )
    )


def test_block_reordering_pe_target_is_skipped_without_writes(tmp_path: Path, caplog) -> None:
    target = tmp_path / _PE_FIXTURE.name
    original_bytes = _PE_FIXTURE.read_bytes()
    shutil.copyfile(_PE_FIXTURE, target)

    with (
        caplog.at_level(logging.WARNING, logger="r2morph.mutations.block_reordering"),
        Binary(target, writable=True) as binary,
    ):
        binary.analyze("aa")
        result = BlockReorderingPass({"probability": 1.0, "seed": 20261109}).apply(binary)

    expect(
        result["mutations_applied"] == 0
        and target.read_bytes() == original_bytes
        and "unsupported target" in caplog.text
    )
