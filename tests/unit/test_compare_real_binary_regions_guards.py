"""Characterization of _compare_real_binary_regions guard paths.

Pins the three pre-angr early returns before the BinaryRegionComparator
extraction (clean-arch slice 3a): missing previous-binary checkpoint,
missing current binary path, and binary artifacts absent on disk.

No mocks / monkeypatch (CLAUDE.md §4): plain SimpleNamespace binary
stand-ins (the method only reads `binary.path`) and real tmp_path
filesystem state for the on-disk check. None of these paths reaches
angr / _setup_symbolic_bridges.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from r2morph.validation.symbolic_validator import SymbolicValidator


def test_missing_previous_binary_path_returns_no_checkpoint() -> None:
    result = SymbolicValidator()._binary_comparator._compare_real_binary_regions(
        SimpleNamespace(path="/whatever"), {}, SimpleNamespace()
    )
    assert result == {
        "symbolic_binary_check_performed": False,
        "symbolic_binary_reason": "no previous binary checkpoint available",
    }


def test_missing_current_binary_path_returns_path_not_available(tmp_path: Path) -> None:
    prev = tmp_path / "prev.bin"
    prev.write_bytes(b"\x7fELF")
    result = SymbolicValidator()._binary_comparator._compare_real_binary_regions(
        SimpleNamespace(),  # no `path` attribute -> getattr(..., "path", None) is None
        {"previous_binary_path": str(prev)},
        SimpleNamespace(),
    )
    assert result == {
        "symbolic_binary_check_performed": False,
        "symbolic_binary_reason": "current binary path not available",
    }


def test_artifacts_absent_on_disk_returns_not_available(tmp_path: Path) -> None:
    missing_prev = tmp_path / "missing_prev.bin"
    missing_curr = tmp_path / "missing_curr.bin"
    result = SymbolicValidator()._binary_comparator._compare_real_binary_regions(
        SimpleNamespace(path=str(missing_curr)),
        {"previous_binary_path": str(missing_prev)},
        SimpleNamespace(),
    )
    assert result == {
        "symbolic_binary_check_performed": False,
        "symbolic_binary_reason": "real binary artifacts not available on disk",
    }


def test_only_previous_missing_on_disk_still_not_available(tmp_path: Path) -> None:
    missing_prev = tmp_path / "missing_prev.bin"
    present_curr = tmp_path / "curr.bin"
    present_curr.write_bytes(b"\x7fELF")
    result = SymbolicValidator()._binary_comparator._compare_real_binary_regions(
        SimpleNamespace(path=str(present_curr)),
        {"previous_binary_path": str(missing_prev)},
        SimpleNamespace(),
    )
    assert result == {
        "symbolic_binary_check_performed": False,
        "symbolic_binary_reason": "real binary artifacts not available on disk",
    }
