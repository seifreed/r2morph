from types import SimpleNamespace

from r2morph.validation.validator_execution import hash_text, normalize_output, run_binary
from r2morph.validation.validator_runtime import ValidationTestCase


def test_normalize_output_and_hash_text() -> None:
    assert normalize_output("foo  \nbar\n", True) == "foo\nbar"
    assert normalize_output("foo  \nbar\n", False) == "foo  \nbar\n"
    assert hash_text("abc") == hash_text("abc")


def test_run_binary_collects_monitored_files(monkeypatch, tmp_path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"binary")
    run_dir = tmp_path / "run"

    case = ValidationTestCase(
        args=["--flag"],
        stdin="input",
        env={"R2MORPH_TEST": "1"},
        expected_exitcode=0,
        description="sample",
        working_dir=str(run_dir),
        monitored_files=["artifact.txt"],
    )

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        (kwargs["cwd"] / "artifact.txt").write_bytes(b"payload")
        return SimpleNamespace(stdout=b"ok", stderr=b"", returncode=7)

    monkeypatch.setattr("r2morph.validation.validator_execution.subprocess.run", fake_run)

    result = run_binary(binary_path, case, timeout=3)

    assert captured["cmd"][0].endswith(binary_path.name)
    assert captured["kwargs"]["timeout"] == 3
    assert result["stdout"] == "ok"
    assert result["stderr"] == ""
    assert result["exitcode"] == 7
    assert result["files"]["artifact.txt"] == b"payload".hex()
