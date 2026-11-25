from __future__ import annotations

import pytest

from r2morph.validation.validator_execution_files import collect_monitored_files
from tests.utils.assertions import expect


def test_collect_monitored_files_reads_hex_contents(tmp_path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "artifact.txt").write_bytes(b"payload")

    expect(collect_monitored_files(run_dir, ["artifact.txt"]) == {"artifact.txt": b"payload".hex()})


def test_collect_monitored_files_ignores_missing_and_non_files(tmp_path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "nested").mkdir()

    expect(collect_monitored_files(run_dir, ["missing.txt", "nested"]) == {})


@pytest.mark.parametrize("path_kind", ["parent", "absolute"])
def test_collect_monitored_files_rejects_paths_outside_runtime_directory(tmp_path, path_kind: str) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    path = "../secret.txt" if path_kind == "parent" else str(tmp_path / "secret.txt")

    with pytest.raises(ValueError, match="must stay within the runtime directory"):
        collect_monitored_files(run_dir, [path])


def test_collect_monitored_files_rejects_symlinks_outside_runtime_directory(tmp_path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("not for the report", encoding="utf-8")
    link = run_dir / "artifact.txt"
    try:
        link.symlink_to(secret)
    except OSError as error:
        pytest.skip(f"file symlinks are unavailable: {error}")

    with pytest.raises(ValueError, match="must stay within the runtime directory"):
        collect_monitored_files(run_dir, ["artifact.txt"])


@pytest.mark.parametrize("path", [None, 7, ""])
def test_collect_monitored_files_rejects_invalid_path_values(tmp_path, path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    with pytest.raises(ValueError, match="must be a non-empty relative path"):
        collect_monitored_files(run_dir, [path])
