"""Regression: Mach-O repair must reach the slices of a fat binary.

``_iter_macho_binaries`` iterated ``FatBinary.it_binaries``, which is a nested
type rather than a property, so the call raised TypeError and a bare handler
turned that into an empty list. Every repair driven through it - bind symbols,
segment permissions - therefore reported nothing to do for a fat binary while
appearing to succeed. A FatBinary is itself the iterable over its slices.
"""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from r2morph.platform.macho_handler_repair import _iter_macho_binaries
from tests.utils.assertions import expect
from tests.utils.process import run_command

lief = pytest.importorskip("lief")

_DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "dataset"
_THIN_FIXTURE = _DATASET / "macho_arm64"


def _fat_binary(tmp_path: Path) -> Path:
    """A real fat Mach-O, built with lipo from the thin dataset fixture."""
    if platform.system() != "Darwin":
        pytest.skip("macOS-only: lipo builds the fat container")
    if shutil.which("lipo") is None:
        pytest.skip("lipo not available")
    if not _THIN_FIXTURE.exists():
        pytest.skip(f"fixture missing: {_THIN_FIXTURE}")

    thin = tmp_path / "thin"
    thin.write_bytes(_THIN_FIXTURE.read_bytes())
    fat = tmp_path / "fat"
    run_command(["lipo", "-create", str(thin), "-output", str(fat)], check=True, timeout=60)
    return fat


def test_iter_macho_binaries_yields_the_slices_of_a_fat_binary(tmp_path: Path) -> None:
    parsed = lief.MachO.parse(str(_fat_binary(tmp_path)))
    expect(isinstance(parsed, lief.MachO.FatBinary), "lipo did not produce a fat container")

    expect(len(_iter_macho_binaries(None, parsed)) == len(parsed))


def test_iter_macho_binaries_yields_a_thin_binary_unchanged(tmp_path: Path) -> None:
    if not _THIN_FIXTURE.exists():
        pytest.skip(f"fixture missing: {_THIN_FIXTURE}")
    thin = tmp_path / "thin"
    thin.write_bytes(_THIN_FIXTURE.read_bytes())
    parsed = lief.MachO.parse(str(thin))
    binary = parsed if isinstance(parsed, lief.MachO.Binary) else parsed.at(0)

    expect(_iter_macho_binaries(None, binary) == [binary])
