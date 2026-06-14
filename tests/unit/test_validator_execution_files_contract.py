from __future__ import annotations

from r2morph.validation.validator_execution_files import collect_monitored_files


def test_collect_monitored_files_reads_hex_contents(tmp_path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "artifact.txt").write_bytes(b"payload")

    assert collect_monitored_files(run_dir, ["artifact.txt"]) == {"artifact.txt": b"payload".hex()}


def test_collect_monitored_files_ignores_missing_and_non_files(tmp_path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "nested").mkdir()

    assert collect_monitored_files(run_dir, ["missing.txt", "nested"]) == {}
