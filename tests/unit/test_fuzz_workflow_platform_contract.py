from pathlib import Path

import yaml

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_FUZZ_WORKFLOW = _ROOT / ".github" / "workflows" / "fuzz.yml"


def test_fuzz_workflow_uses_bash_for_windows_wheel_install() -> None:
    workflow = yaml.safe_load(_FUZZ_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["parser-and-rewriter"]["steps"]
    wheel_step = next(step for step in steps if step["name"] == "Build and install package wheel")

    expect(wheel_step["shell"] == "bash")


def test_fuzz_workflow_installs_keystone_library_on_macos() -> None:
    workflow = yaml.safe_load(_FUZZ_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["parser-and-rewriter"]["steps"]
    keystone_step = next(step for step in steps if step["name"] == "Install Keystone native library")

    expect(
        keystone_step["if"] == "runner.os == 'macOS'"
        and "brew install keystone" in keystone_step["run"]
        and "DYLD_LIBRARY_PATH=$(brew --prefix keystone)/lib" in keystone_step["run"]
    )
