from __future__ import annotations

from r2morph.validation.validator_results_artifacts import build_compared_signals, build_output_hashes
from r2morph.validation.validator_runtime import RuntimeComparisonConfig


def test_build_compared_signals_uses_comparison_flags() -> None:
    comparison = RuntimeComparisonConfig(
        compare_exitcode=True,
        compare_stdout=False,
        compare_stderr=True,
        compare_files=False,
        normalize_whitespace=True,
    )

    assert build_compared_signals(comparison) == {
        "exitcode": True,
        "stdout": False,
        "stderr": True,
        "files": False,
        "normalize_whitespace": True,
    }


def test_build_output_hashes_is_stable() -> None:
    comparison = RuntimeComparisonConfig(normalize_whitespace=True)
    hashes = build_output_hashes(
        [{"stdout": "out \n", "stderr": "err\n"}],
        [{"stdout": "out\n", "stderr": "err\n"}],
        comparison,
    )

    assert hashes["original_stdout_sha256"] != hashes["mutated_stdout_sha256"]
    assert hashes["normalized_original_stdout_sha256"] == hashes["normalized_mutated_stdout_sha256"]
    assert "normalized_original_stdout_sha256" in hashes
