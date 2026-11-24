"""The workflow patch repairs the pinned corpus's AVX memory sample."""

from __future__ import annotations

from pathlib import Path

from tests.utils.assertions import expect

_ROOT = Path(__file__).resolve().parents[2]
_PATCH = _ROOT / ".github" / "patches" / "r2morph-corpus-avx-packed-memory.patch"
_WORKFLOW = _ROOT / ".github" / "workflows" / "differential-corpus.yml"


def test_pinned_public_corpus_patch_repairs_the_memory_argument_type() -> None:
    patch = _PATCH.read_text(encoding="utf-8")
    old_memory_argument = (
        "-    const int memory_mask = " "_mm256_movemask_ps(compare_float_memory(float256_left, float256_right));"
    )
    new_memory_argument = (
        "+    const int memory_mask = "
        "_mm256_movemask_ps(compare_float_memory(float256_left, float256_right_values));"
    )
    expect(
        "-    const __m256 float256_right =" in patch
        and "+    const float float256_right_values[8] =" in patch
        and "+    const __m256 float256_right = _mm256_loadu_ps(float256_right_values);" in patch
        and old_memory_argument in patch
        and new_memory_argument in patch
    )


def test_public_corpus_workflow_applies_patch_and_rejects_any_omitted_build() -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")

    expect(
        "Patch AVX memory fixture type mismatch" in workflow
        and "r2morph-corpus-avx-packed-memory.patch" in workflow
        and "public corpus has omitted compiler outputs" in workflow
        and "built_sources != expected_sources" in workflow
        and 'source_count"] != expected_source_count' in workflow
    )
