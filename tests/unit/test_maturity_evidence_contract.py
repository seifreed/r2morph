from __future__ import annotations

from pathlib import Path

from scripts.maturity_evidence import build_evidence, merge_decompiler_evidence, read_composition_evidence
from tests.utils.assertions import expect

_EXPECTED_DECOMPILER_BLOCKERS = 2
_EXPECTED_DIRECTIONAL_PAIR_COUNT = 3


def _summary(applied_runs: int, *, incomplete_observations: int = 0) -> dict[str, object]:
    return {
        "applied_runs": applied_runs,
        "behavioral_validation_observations": applied_runs,
        "behavioral_false_positive_observations": 0,
        "behavioral_validation_missing_observations": incomplete_observations,
        "behavioral_false_positive_rate_percent": 0.0,
        "independent_semantic_observations": applied_runs,
        "independent_semantic_false_positive_observations": 0,
        "independent_semantic_missing_observations": incomplete_observations,
        "independent_semantic_false_positive_rate_percent": 0.0,
        "affected_instruction_applied_runs": applied_runs,
        "affected_instruction_missing_runs": 0,
        "affected_instruction_mnemonics": ["mov"] if applied_runs else [],
        "affected_instruction_record_count": applied_runs,
        "output_size_coverage_percent": 100.0,
        "transform_duration_coverage_percent": 100.0,
        "runtime_duration_coverage_percent": 100.0,
        "static_metric_coverage_percent": 100.0,
    }


def test_maturity_evidence_preserves_preview_and_partial_statuses(tmp_path: Path) -> None:
    composition = tmp_path / "composition.xml"
    composition.write_text(
        """<?xml version='1.0'?><testsuite tests='3'>
        <testcase name='test_extended_passes_compose_after_nop_without_corrupting_fixture[AntiDisassembly]'/>
        <testcase name='test_extended_passes_compose_before_nop_without_corrupting_fixture[AntiDisassembly]'/>
        <testcase name='test_extended_passes_compose_after_nop_without_corrupting_fixture[StackStrings]'/>
        </testsuite>""",
        encoding="utf-8",
    )
    composition_evidence = read_composition_evidence((composition,))
    differential = {
        "pass_names": ["AntiDisassembly", "StackStrings"],
        "summary": {
            "AntiDisassembly": _summary(2),
            "StackStrings": _summary(1),
        },
    }
    extended = {"pass_names": [], "summary": {}}
    evidence = build_evidence(differential, extended, composition_evidence)

    expect(
        evidence["passes"]["AntiDisassembly"]["composition"]["status"] == "complete"
        and evidence["passes"]["StackStrings"]["composition"]["status"] == "complete"
        and evidence["passes"]["StackStrings"]["performance"]["status"] == "complete"
        and composition_evidence["directional_pair_count"] == _EXPECTED_DIRECTIONAL_PAIR_COUNT
        and evidence["summary"]["blocker_totals"]["decompiler"] == _EXPECTED_DECOMPILER_BLOCKERS
    )


def test_composition_evidence_keeps_simple_pair_direction(tmp_path: Path) -> None:
    composition = tmp_path / "composition.xml"
    composition.write_text(
        "<testsuite><testcase name='test_composed_real_passes_preserve_exit_code[nop_then_constant]'/>"
        "<testcase name='test_composed_real_passes_preserve_exit_code[constant_then_nop]'/></testsuite>",
        encoding="utf-8",
    )

    evidence = read_composition_evidence((composition,))

    expect(evidence["pair_case_counts"] == {"ConstantUnfolding->NopInsertion": 1, "NopInsertion->ConstantUnfolding": 1})


def test_maturity_evidence_marks_missing_behavioral_observation_as_incomplete(tmp_path: Path) -> None:
    composition = tmp_path / "composition.xml"
    composition.write_text(
        "<testsuite><testcase name='test_composed_real_passes_preserve_exit_code[nop_then_substitution]'/></testsuite>",
        encoding="utf-8",
    )
    report = {
        "pass_names": ["NopInsertion"],
        "summary": {"NopInsertion": _summary(1, incomplete_observations=1)},
    }
    evidence = build_evidence(report, {"pass_names": [], "summary": {}}, read_composition_evidence((composition,)))

    expect(evidence["passes"]["NopInsertion"]["behavioral_false_positive"]["status"] == "incomplete")


def test_maturity_evidence_requires_independent_semantic_observation(tmp_path: Path) -> None:
    composition = tmp_path / "composition.xml"
    composition.write_text(
        "<testsuite><testcase name='test_composed_real_passes_preserve_exit_code[nop_then_substitution]'/></testsuite>",
        encoding="utf-8",
    )
    summary = _summary(1)
    summary["independent_semantic_observations"] = 0
    summary["independent_semantic_missing_observations"] = 1
    report = {"pass_names": ["NopInsertion"], "summary": {"NopInsertion": summary}}

    evidence = build_evidence(report, {"pass_names": [], "summary": {}}, read_composition_evidence((composition,)))

    expect(evidence["passes"]["NopInsertion"]["behavioral_false_positive"]["status"] == "incomplete")


def test_differential_workflow_publishes_maturity_evidence() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "differential-corpus.yml"

    expect(
        "scripts/maturity_evidence.py" in workflow.read_text(encoding="utf-8")
        and "maturity-evidence-merged.json" in workflow.read_text(encoding="utf-8")
    )


def test_adversarial_workflow_attaches_upstream_decompiler_evidence() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "adversarial-benchmark.yml"
    content = workflow.read_text(encoding="utf-8")

    expect(
        "differential_run_id:" in content
        and "inputs.differential_run_id != ''" in content
        and "pattern: differential-corpus-merged-*" in content
        and "--count 10" in content
        and (
            "run-id: ${{ github.event_name == 'workflow_run' && github.event.workflow_run.id || "
            "inputs.differential_run_id }}"
        )
        in content
        and "--base-evidence" in content
        and "maturity-evidence-with-adversarial.json" in content
    )


def test_merge_decompiler_evidence_recomputes_decompiler_blockers() -> None:
    base = {
        "passes": {
            "NopInsertion": {
                "performance": {"status": "complete"},
                "behavioral_false_positive": {"status": "measured"},
                "affected_instructions": {"status": "measured"},
                "composition": {"status": "complete"},
                "decompiler": {"status": "pending"},
            }
        },
        "summary": {"blockers": {"decompiler": ["NopInsertion"]}, "blocker_totals": {"decompiler": 1}},
    }
    adversarial = {
        "summary": {
            "analyzer_effectiveness_by_pass": {
                "NopInsertion": {
                    "radare2": {
                        "completion_percent": 100.0,
                        "decompiler": {"observed_pairs": 1, "completion_percent": 100.0},
                    },
                    "objdump": {"completion_percent": 100.0},
                }
            }
        }
    }

    evidence = merge_decompiler_evidence(base, adversarial)

    expect(
        evidence["passes"]["NopInsertion"]["decompiler"]["status"] == "comparable"
        and evidence["summary"]["blocker_totals"]["decompiler"] == 0
        and evidence["summary"]["adversarial_evidence_attached"] is True
    )


def test_maturity_evidence_rejects_completed_non_decompiler_tool_as_decompiler_proof() -> None:
    evidence = merge_decompiler_evidence(
        {
            "passes": {"NopInsertion": {"decompiler": {"status": "pending"}}},
            "summary": {"blockers": {}, "blocker_totals": {}},
        },
        {"summary": {"analyzer_effectiveness_by_pass": {"NopInsertion": {"objdump": {"completion_percent": 100.0}}}}},
    )

    expect(
        evidence["passes"]["NopInsertion"]["decompiler"]["status"] == "pending"
        and evidence["summary"]["blocker_totals"]["decompiler"] == 1
    )
