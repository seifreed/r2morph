"""Regression coverage for the verified target boundary of block reordering."""

from r2morph.mutations.block_reordering import BlockReorderingPass
from tests.utils.assertions import expect


def test_block_reordering_keeps_non_elf_targets_as_previews() -> None:
    support = BlockReorderingPass().get_support()

    expect(
        support.formats == ("ELF", "Mach-O", "PE")
        and support.architectures == ("x86_64",)
        and support.stability == "stable"
        and support.notes
        == (
            "ELF x86-32 remains preview pending broader native corpus evidence.",
            "Mach-O x86_64 remains preview pending broader native corpus evidence.",
            "PE x86_64 remains preview pending broader native corpus evidence.",
        )
    )
