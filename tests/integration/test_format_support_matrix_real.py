"""
Real format-level support matrix tests.
"""

from __future__ import annotations

import importlib.util

import pytest

from r2morph.core.binary import Binary
from r2morph.core.support import PRODUCT_SUPPORT, classify_target_support

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)


def test_dataset_macho_sample_is_visible_but_outside_stable_support(deterministic_macho_sample):
    with Binary(deterministic_macho_sample) as binary:
        binary.analyze("aa")
        arch_info = binary.get_arch_info()

    assert "mach" in arch_info["format"].lower()
    assert "Mach-O" not in PRODUCT_SUPPORT.stable_formats
    support = classify_target_support("Mach-O", arch_info["arch"], arch_info.get("bits"))
    assert support["tier"] == "prolonged-experimental"
    assert support["format"] == "Mach-O"


def test_dataset_pe_sample_is_visible_but_outside_stable_support(deterministic_pe_sample):
    with Binary(deterministic_pe_sample) as binary:
        binary.analyze("aa")
        arch_info = binary.get_arch_info()

    assert "pe" in arch_info["format"].lower()
    assert "PE" not in PRODUCT_SUPPORT.stable_formats
    support = classify_target_support("PE", arch_info["arch"], arch_info.get("bits"))
    assert support["tier"] == "prolonged-experimental"
    assert support["format"] == "PE"


def test_elf_fixture_is_inside_stable_support(deterministic_substitute_elf):
    with Binary(deterministic_substitute_elf) as binary:
        binary.analyze("aa")
        arch_info = binary.get_arch_info()

    support = classify_target_support("ELF", arch_info["arch"], arch_info.get("bits"))
    assert support["tier"] == "stable"
    assert support["architecture"] == "x86_64"
