"""Contract for isolated native Mach-O execution in cross-platform CI."""

from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]


def test_macos_native_macho_smoke_runs_in_a_fresh_bounded_pytest_process() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    cross_platform_job = workflow.split("  cross-platform-tests:", 1)[1].split("  package-smoke:", 1)[0]
    native_test = (_ROOT / "tests" / "integration" / "test_macho_x86_64_native.py").read_text(encoding="utf-8")
    dead_code_test = (_ROOT / "tests" / "integration" / "test_macho_x86_64_dead_code.py").read_text(encoding="utf-8")
    constant_test = (_ROOT / "tests" / "integration" / "test_macho_x86_64_constant_unfolding.py").read_text(
        encoding="utf-8"
    )

    expect(
        "macos-latest" in cross_platform_job
        and "macos-15-intel" in cross_platform_job
        and 'platform.machine().lower() in {"x86_64", "amd64"}' in cross_platform_job
        and '"tests/integration/test_macho_x86_64_native.py"' in cross_platform_job
        and '"tests/integration/test_macho_x86_64_dead_code.py"' in cross_platform_job
        and '"tests/integration/test_macho_x86_64_constant_unfolding.py"' in cross_platform_job
        and "Install Rosetta" not in cross_platform_job
        and 'test_targets.append("tests/integration/test_macho_x86_64_native.py")' not in cross_platform_job
        and '[*pytest_command, *test_targets, "--no-cov", "--tb=short"]' in cross_platform_job
        and '[*pytest_command, *native_macho_target, "--no-cov", "--tb=short"]' in cross_platform_job
        and "timeout=120" in cross_platform_job
        and 'platform.machine().lower() not in {"x86_64", "amd64"}' in native_test
        and "test_macho_x86_64_dead_code_injection_preserves_native_observables" in dead_code_test
        and 'platform.machine().lower() not in {"x86_64", "amd64"}' in constant_test
        and "ConstantUnfoldingPass" in constant_test
    )
