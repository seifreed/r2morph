import sys

from r2morph.validation.validator_execution import run_binary
from r2morph.validation.validator_execution_text import hash_text, normalize_output
from r2morph.validation.validator_runtime import ValidationTestCase
from tests.utils.assertions import expect


def test_normalize_output_and_hash_text() -> None:
    expect(normalize_output("foo  \nbar\n", True) == "foo\nbar")
    expect(normalize_output("foo  \nbar\n", False) == "foo  \nbar\n")
    expect(hash_text("abc") == hash_text("abc"))


def test_run_binary_with_runtime_context_returns_observed_result(tmp_path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "valid = sys.argv[1:] == ['--flag'] and sys.stdin.read() == 'input'\n"
        "valid = valid and os.environ.get('R2MORPH_TEST') == '1'\n"
        "pathlib.Path('artifact.txt').write_bytes(b'payload')\n"
        "print('ok' if valid else 'invalid')\n"
        "raise SystemExit(7 if valid else 9)\n"
    )
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

    result = run_binary(binary_path, case, timeout=3)

    expect(result == {"stdout": "ok\n", "stderr": "", "exitcode": 7, "files": {"artifact.txt": b"payload".hex()}})
