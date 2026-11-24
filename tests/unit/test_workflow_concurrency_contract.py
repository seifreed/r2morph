from pathlib import Path

import yaml

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_DEPENDENCY_WORKFLOWS = (
    _ROOT / ".github" / "workflows" / "ci.yml",
    _ROOT / ".github" / "workflows" / "release.yml",
    _ROOT / ".github" / "workflows" / "adversarial-benchmark.yml",
)
_EXPECTED_CROSS_PLATFORM_TIMEOUT_MINUTES = 30


def test_ubuntu_package_index_updates_are_time_bounded() -> None:
    for workflow_path in _DEPENDENCY_WORKFLOWS:
        commands = workflow_path.read_text(encoding="utf-8").splitlines()
        updates = [line.strip() for line in commands if "sudo apt-get" in line and line.rstrip().endswith(" update")]

        expect(
            updates
            and all(
                line.startswith(
                    "timeout 10m sudo apt-get -o Acquire::Retries=3 "
                    "-o Acquire::http::Timeout=60 -o Acquire::https::Timeout=60 update"
                )
                for line in updates
            )
        )


def test_ubuntu_dependency_installations_are_time_bounded() -> None:
    for workflow_path in _DEPENDENCY_WORKFLOWS:
        commands = workflow_path.read_text(encoding="utf-8").splitlines()
        installs = [line.strip() for line in commands if "sudo apt-get" in line and "install -y" in line]

        expect(
            installs
            and all(
                line.startswith(
                    "timeout 15m sudo apt-get -o Acquire::Retries=3 "
                    "-o Acquire::http::Timeout=60 -o Acquire::https::Timeout=60 install -y"
                )
                for line in installs
            )
        )


def test_adversarial_workflow_preserves_active_campaigns() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "adversarial-benchmark.yml").read_text(encoding="utf-8")

    expect("group: adversarial-benchmark-${{ github.ref }}" in workflow and "cancel-in-progress: false" in workflow)


def test_ci_supersedes_obsolete_push_validation() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    expect(
        "group: ${{ github.workflow }}-${{ github.ref }}-" in workflow
        and "github.event_name == 'push' && 'push' || github.run_id" in workflow
        and "cancel-in-progress: true" in workflow
    )


def test_ci_bounds_cross_platform_unit_test_step() -> None:
    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    step = next(
        step
        for step in workflow["jobs"]["cross-platform-tests"]["steps"]
        if step.get("name") == "Run cross-platform unit tests"
    )

    expect(
        step["timeout-minutes"] == _EXPECTED_CROSS_PLATFORM_TIMEOUT_MINUTES and "faulthandler_timeout=60" in step["run"]
    )


def test_fuzz_supersedes_obsolete_push_campaigns() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "fuzz.yml").read_text(encoding="utf-8")

    expect(
        "group: continuous-fuzz-${{ github.ref }}-" in workflow
        and "github.event_name == 'push' && 'push' || github.run_id" in workflow
        and "cancel-in-progress: true" in workflow
    )
