from pathlib import Path

import yaml

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW = _ROOT / ".github" / "workflows" / "differential-corpus.yml"


def test_windows_differential_installs_i686_compiler() -> None:
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["cross-platform-format-windows"]["steps"]
    setup = next(step for step in steps if step.get("id") == "msys2")

    expect(
        setup["uses"] == "msys2/setup-msys2@v2"
        and setup["with"]["msystem"] == "MINGW32"
        and "mingw-w64-i686-gcc" in setup["with"]["install"]
    )


def test_windows_differential_exposes_i686_compiler_on_path() -> None:
    workflow = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["cross-platform-format-windows"]["steps"]
    expose = next(step for step in steps if step["name"] == "Expose 32-bit PE compiler")

    expect("i686-w64-mingw32-gcc.exe" in expose["run"] and "GITHUB_PATH" in expose["run"])
