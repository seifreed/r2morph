from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace

from r2morph.core.engine import MorphEngine
from r2morph.core.report_helpers_coverage import _summarize_pass_coverage_buckets
from r2morph.core.report_helpers_evidence import (
    _build_evidence_summary_for_pass,
    _build_pass_region_evidence_map,
    _summarize_pass_evidence,
    _summarize_structural_evidence,
)
from r2morph.core.report_helpers_risk import _summarize_pass_risk_buckets
from r2morph.core.report_helpers_summary_metrics import (
    _summarize_diff_digest,
    _summarize_pass_timings,
)
from r2morph.core.report_helpers_symbolic_summary import (
    _build_symbolic_summary_for_pass,
    _summarize_symbolic_coverage_by_pass,
    _summarize_symbolic_issue_passes,
    _summarize_symbolic_severity_by_pass,
)
from r2morph.core.report_helpers_validation import (
    _build_pass_validation_context,
    _enrich_validation_policy,
    _summarize_degradation_roles,
)
from r2morph.core.support import classify_target_support
from r2morph.mutations.base import MutationPass
from r2morph.pipeline import Pipeline, PipelineRunOptions
from r2morph.reporting.gate_evaluator import (
    build_gate_failure_priority as _build_gate_failure_priority,
)
from r2morph.reporting.gate_evaluator import (
    build_gate_failure_severity_priority as _build_gate_failure_severity_priority,
)
from r2morph.reporting.gate_evaluator import (
    summarize_gate_failures as _summarize_gate_failures,
)
from r2morph.validation.manager import ValidationIssue, ValidationManager, ValidationOutcome
from tests.utils.assertions import expect, expect_all
from tests.utils.field_names import MUTATION_NAME_KEY, ONLY_MUTATION_KEY

_EXPECTED_MANAGER_SYMBOLIC_VALIDATOR_SCOPE_GATE_ESTIMAT_2 = 2
_EXPECTED_MANAGER_SYMBOLIC_VALIDATOR_SCOPE_GATE_ESTIMAT_3 = 3
_EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_MUTATED_REG_3 = 3
_EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_MUTATED_REG_4198419 = 0x401013
_EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_ORIGINAL_RE_4198419 = 0x401013
_EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_REGION_EXIT_4 = 4
_EXPECTED_REPORT_DIFF_DIGEST_CHANGED_BYTES_2 = 2
_EXPECTED_REPORT_SUMMARY_PASS_TIMING_SUMMARY_0_EXECUTIO_0_25 = 0.25
_EXPECTED_REPORT_TIMINGS_EXECUTION_TIME_SECONDS_1_25 = 1.25
_EXPECTED_RESULT_PASS_RESULTS_RECORDINGPASS_DIFF_SUMMAR_2 = 2
_EXPECTED_ROWS_0_SYMBOLIC_REQUESTED_2 = 2
_EXPECTED_SUMMARY_MAX_MUTATED_TRACE_LENGTH_4 = 4
_EXPECTED_SUMMARY_MAX_ORIGINAL_TRACE_LENGTH_2 = 2
_EXPECTED_TIMINGS_0_EXECUTION_TIME_SECONDS_0_25 = 0.25


class _FakeBinary:
    def __init__(self):
        self.reload_calls = 0
        self.bytes = {0x401010: b"\x91\x91"}

    def reload(self):
        self.reload_calls += 1

    def read_bytes(self, addr: int, size: int) -> bytes:
        return self.bytes.get(addr, b"\x00" * size)[:size]

    def get_function_disasm(self, function_address: int):
        return [{"addr": function_address, "disasm": "nop", "size": 1}]

    def get_basic_blocks(self, function_address: int):
        return [{"addr": function_address, "size": 1}]

    def get_arch_info(self):
        return {"arch": "x86", "bits": 64, "format": "ELF"}


class _FakeSession:
    def __init__(self):
        self.checkpoints: list[str] = []
        self.rollbacks: list[str] = []
        self._checkpoint_objects: list[SimpleNamespace] = []

    def checkpoint(self, name: str, description: str = ""):
        self.checkpoints.append(name)
        self._checkpoint_objects.append(SimpleNamespace(name=name, binary_path=Path("test-data/fake.bin")))

    def rollback_to(self, name: str) -> bool:
        self.rollbacks.append(name)
        return True

    def list_checkpoints(self):
        return self._checkpoint_objects


class _FakeValidationManager:
    def __init__(self, *, passed: bool):
        self.passed = passed

    def validate_pass(self, binary, pass_result):
        if self.passed:
            return ValidationOutcome(
                validator_type="structural",
                passed=True,
                scope="pass",
            )
        return ValidationOutcome(
            validator_type="structural",
            passed=False,
            scope="pass",
            issues=[
                ValidationIssue(
                    validator="structural",
                    message="invalid mutation",
                    address_range=(0x401010, 0x401011),
                )
            ],
        )


class _RecordingPass(MutationPass):
    def __init__(self):
        super().__init__("RecordingPass")

    def apply(self, binary):
        self._record_mutation(
            function_address=0x401000,
            start_address=0x401010,
            end_address=0x401011,
            original_bytes=b"\x90\x90",
            mutated_bytes=b"\x91\x91",
            original_disasm="nop; nop",
            mutated_disasm="xchg ecx, eax",
            mutation_kind="instruction_substitution",
            metadata={"source": "test"},
        )
        return {"mutations_applied": 1}


class _InstructionSubstitutionSemanticPass(MutationPass):
    def __init__(self):
        super().__init__("InstructionSubstitution")

    def apply(self, binary):
        self._record_mutation(
            function_address=0x401000,
            start_address=0x401010,
            end_address=0x401011,
            original_bytes=b"\x90\x90",
            mutated_bytes=b"\x91\x91",
            original_disasm="xor eax, eax",
            mutated_disasm="sub eax, eax",
            mutation_kind="instruction_substitution",
            metadata={
                "structural_baseline": {},
                "equivalence_arch": "x86",
                "equivalence_group_index": 7,
                "equivalence_group_size": 2,
                "equivalence_original_pattern": "xor eax, eax",
                "equivalence_replacement_pattern": "sub eax, eax",
                "equivalence_members": ["xor eax, eax", "sub eax, eax"],
            },
        )
        return {"mutations_applied": 1}


def test_pipeline_accumulates_mutation_history():
    pipeline = Pipeline()
    pipeline.add_pass(_RecordingPass())

    result = pipeline.run(
        _FakeBinary(),
        PipelineRunOptions(
            session=_FakeSession(),
            validation_manager=_FakeValidationManager(passed=True),
        ),
    )

    expect(result["total_mutations"] == 1)
    expect(len(result["mutations"]) == 1)
    expect(result["mutations"][0][MUTATION_NAME_KEY] == "RecordingPass")
    expect(not (result["validation"]["all_passed"] is not True))
    expect(
        result["pass_results"]["RecordingPass"]["diff_summary"]["changed_bytes"]
        == _EXPECTED_RESULT_PASS_RESULTS_RECORDINGPASS_DIFF_SUMMAR_2
    )
    expect(
        result["pass_results"]["RecordingPass"]["diff_summary"]["region_details"]
        == [
            {
                "address_range": [4198416, 4198417],
                "mutation_kind": "instruction_substitution",
                "byte_diff_count": 2,
                "function_address": 4198400,
            }
        ]
    )
    expect(result["pass_results"]["RecordingPass"]["diff_summary"]["structural_issue_count"] == 0)


def test_classify_target_support_reports_stable_and_prolonged_experimental():
    stable = classify_target_support("ELF", "x86_64")
    macho = classify_target_support("Mach-O", "arm64")
    pe = classify_target_support("PE", "x86_64")
    compat = classify_target_support("ELF", "x86", 64)
    unknown = classify_target_support("flat", "mips")

    expect(stable["tier"] == "stable")
    expect(compat["tier"] == "stable")
    expect(compat["architecture"] == "x86_64")
    expect(macho["tier"] == "prolonged-experimental")
    expect(pe["tier"] == "prolonged-experimental")
    expect(unknown["tier"] == "unsupported")


def test_report_summaries_include_timings_and_diff_digest():
    pass_results = {
        "InstructionSubstitution": {
            "execution_time_seconds": 0.25,
            "rolled_back": False,
            "mutations": [
                {
                    "pass_name": "InstructionSubstitution",
                    "start_address": 0x401010,
                    "end_address": 0x401012,
                }
            ],
            "validation": {"issues": [{}]},
            "diff_summary": {
                "changed_regions": [[0x401010, 0x401012]],
                "changed_bytes": 2,
                "mutation_kinds": ["instruction_substitution"],
            },
        },
        "NopInsertion": {
            "execution_time_seconds": 0.1,
            "rolled_back": True,
            "mutations": [],
            "validation": {"issues": []},
            "diff_summary": {
                "changed_regions": [[0x401020, 0x401021], [0x401030, 0x401031]],
                "changed_bytes": 2,
                "mutation_kinds": ["nop_insertion"],
            },
        },
    }

    timings = _summarize_pass_timings(pass_results)
    digest = _summarize_diff_digest(pass_results)

    expect(timings[0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(timings[0]["execution_time_seconds"] == _EXPECTED_TIMINGS_0_EXECUTION_TIME_SECONDS_0_25)
    expect(timings[0]["validation_issue_count"] == 1)
    expect(not (timings[1]["rolled_back"] is not True))
    expect(
        digest
        == {
            "changed_region_count": 3,
            "changed_bytes": 4,
            "mutation_kinds": ["instruction_substitution", "nop_insertion"],
            "passes_with_changes": [
                {"pass_name": "NopInsertion", "changed_region_count": 2, "changed_bytes": 2},
                {"pass_name": "InstructionSubstitution", "changed_region_count": 1, "changed_bytes": 2},
            ],
        }
    )


def test_summarize_structural_evidence_compacts_regions():
    digest = _summarize_structural_evidence(
        [
            {
                "address_range": [0x401010, 0x401011],
                "validators": ["structural", "patch_integrity"],
                "messages": ["invalid mutation", "patched bytes differ"],
                "severities": ["error", "error"],
            },
            {
                "address_range": [0x401020, 0x401021],
                "validators": ["structural"],
                "messages": ["stack balanced"],
                "severities": ["info"],
            },
        ]
    )

    expect(
        digest
        == {
            "region_count": 2,
            "validators": ["patch_integrity", "structural"],
            "severity_counts": {"error": 2, "info": 1},
            "sample_messages": ["invalid mutation", "patched bytes differ", "stack balanced"],
        }
    )


def test_engine_build_report_includes_gate_failure_summary():
    engine = MorphEngine()
    report = engine.build_report(
        {
            "input_path": "test-data/original.bin",
            "working_path": "test-data/working.bin",
            "validation_mode": "structural",
            "requested_validation_mode": "structural",
            "pass_results": {},
            "mutations": [],
            "gate_evaluation": {
                "requested": {
                    "min_severity": "clean",
                    "require_pass_severity": [{"pass_name": "NopInsertion", "max_severity": "clean"}],
                },
                "results": {
                    "min_severity_passed": False,
                    "require_pass_severity_passed": False,
                    "require_pass_severity_failures": ["NopInsertion=not-requested(expected <= clean)"],
                    "all_passed": False,
                },
            },
        }
    )

    expected = _summarize_gate_failures(report["gate_evaluation"])
    expected_priority = _build_gate_failure_priority(expected)
    expected_severity_priority = _build_gate_failure_severity_priority(expected)
    expect(report["gate_failures"] == expected)
    expect(report["gate_failure_priority"] == expected_priority)
    expect(report["gate_failure_severity_priority"] == expected_severity_priority)
    expect(report["summary"]["gate_failures"] == expected)
    expect(report["summary"]["gate_failure_priority"] == expected_priority)
    expect(report["summary"]["gate_failure_severity_priority"] == expected_severity_priority)
    expect(report["summary"]["gate_evaluation"] == report["gate_evaluation"]["results"])
    expect(
        report["support_profile"]
        == {
            "format": "",
            "architecture": "",
            "tier": "unsupported",
            "reason": "outside stable and prolonged experimental target sets",
            "stable_target": {"format": "ELF", "architecture": "x86_64"},
            "secondary_cli_namespace": "experimental",
            "prolonged_experimental_areas": [
                "cross-format rewriting outside ELF",
                "non-x86_64 production support (arm64, arm32, x86_32)",
                "semantic validation beyond bounded symbolic scope",
            ],
        }
    )
    expect(report["timings"]["passes"] == [])
    expect(report["summary"]["pass_timing_summary"] == [])
    expect(
        report["diff_digest"]
        == {"changed_region_count": 0, "changed_bytes": 0, "mutation_kinds": [], "passes_with_changes": []}
    )
    expect(
        report["structural_evidence"]
        == {"region_count": 0, "validators": [], "severity_counts": {}, "sample_messages": []}
    )


def test_engine_build_report_includes_support_profile_timings_and_diff_digest():
    engine = MorphEngine()
    report = engine.build_report(
        {
            "input_path": "test-data/original.bin",
            "working_path": "test-data/working.bin",
            "arch": "x86_64",
            "bits": 64,
            "format": "ELF",
            "functions": 3,
            "execution_time_seconds": 1.25,
            "validation_mode": "symbolic",
            "requested_validation_mode": "symbolic",
            "pass_results": {
                "InstructionSubstitution": {
                    "execution_time_seconds": 0.25,
                    "rolled_back": False,
                    "mutations": [
                        {
                            "pass_name": "InstructionSubstitution",
                            "start_address": 0x401010,
                            "end_address": 0x401012,
                            "metadata": {
                                "symbolic_requested": True,
                                "symbolic_observable_check_performed": True,
                                "symbolic_observable_equivalent": True,
                            },
                        }
                    ],
                    "validation": {"issues": []},
                    "diff_summary": {
                        "changed_regions": [[0x401010, 0x401012]],
                        "changed_bytes": 2,
                        "mutation_kinds": ["instruction_substitution"],
                        "structural_regions": [
                            {
                                "address_range": [0x401010, 0x401012],
                                "validators": ["structural"],
                                "messages": ["ok"],
                                "severities": ["info"],
                            }
                        ],
                    },
                }
            },
            "mutations": [
                {
                    "pass_name": "InstructionSubstitution",
                    "metadata": {
                        "symbolic_requested": True,
                        "symbolic_observable_check_performed": True,
                        "symbolic_observable_equivalent": True,
                    },
                }
            ],
        }
    )

    expect(report["support_profile"]["tier"] == "stable")
    expect(report["support_profile"]["secondary_cli_namespace"] == "experimental")
    expect(report["summary"]["support_profile"]["tier"] == "stable")
    expect(report["timings"]["execution_time_seconds"] == _EXPECTED_REPORT_TIMINGS_EXECUTION_TIME_SECONDS_1_25)
    expect(report["timings"]["passes"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(
        report["summary"]["pass_timing_summary"][0]["execution_time_seconds"]
        == _EXPECTED_REPORT_SUMMARY_PASS_TIMING_SUMMARY_0_EXECUTIO_0_25
    )
    expect(report["diff_digest"]["changed_region_count"] == 1)
    expect(report["diff_digest"]["changed_bytes"] == _EXPECTED_REPORT_DIFF_DIGEST_CHANGED_BYTES_2)
    expect(
        report["summary"]["structural_regions"]
        == [
            {
                "address_range": [4198416, 4198418],
                "validators": ["structural"],
                "messages": ["ok"],
                "severities": ["info"],
            }
        ]
    )
    expect(
        report["structural_evidence"]
        == {"region_count": 1, "validators": ["structural"], "severity_counts": {"info": 1}, "sample_messages": ["ok"]}
    )


def test_pipeline_rolls_back_failed_pass_validation():
    session = _FakeSession()
    binary = _FakeBinary()
    pipeline = Pipeline()
    pipeline.add_pass(_RecordingPass())

    result = pipeline.run(
        binary,
        PipelineRunOptions(
            session=session,
            validation_manager=_FakeValidationManager(passed=False),
            rollback_policy="skip-invalid-pass",
        ),
    )

    expect(result["total_mutations"] == 0)
    expect(result["rolled_back_passes"] == 1)
    expect(result["discarded_mutations"] == 1)
    expect(not (result["pass_results"]["RecordingPass"]["rolled_back"] is not True))
    expect(result["pass_results"]["RecordingPass"]["rollback_reason"] == "validation_failed")
    expect(result["pass_results"]["RecordingPass"]["discarded_mutations"] == 1)
    expect(result["mutations"] == [])
    expect(session.rollbacks == ["pass_1_recordingpass"])
    expect(binary.reload_calls == 1)
    expect(result["discarded_mutations_detail"][0]["metadata"]["discard_reason"] == "validation_failed")
    expect(
        result["pass_results"]["RecordingPass"]["diff_summary"]["structural_regions"]
        == [
            {
                "address_range": [4198416, 4198417],
                "validators": ["structural"],
                "messages": ["invalid mutation"],
                "severities": ["error"],
            }
        ]
    )


def test_validation_manager_reports_patch_integrity_mismatch():
    class _MismatchBinary(_FakeBinary):
        def read_bytes(self, addr: int, size: int) -> bytes:
            return b"\x00" * size

    manager = ValidationManager(mode="structural")
    outcome = manager.validate_mutation(
        _MismatchBinary(),
        {
            "pass_name": "RecordingPass",
            "function_address": 0x401000,
            "start_address": 0x401010,
            "end_address": 0x401011,
            "mutated_bytes": "9191",
            "metadata": {"structural_baseline": {}},
        },
    )

    expect(not (outcome.passed is not False))
    expect(any(issue.validator == "patch_integrity" for issue in outcome.issues))


def test_symbolic_region_step_budget_uses_pass_kind_and_disassembly():
    manager = ValidationManager(mode="symbolic")

    expect(
        manager._symbolic_validator._scope_gate._estimate_symbolic_region_steps(
            "InstructionSubstitution",
            {
                "start_address": 4198400,
                "end_address": 4198401,
                "original_disasm": "xor eax, eax",
                "mutated_disasm": "sub eax, eax",
            },
        )
        == 1
    )
    expect(
        manager._symbolic_validator._scope_gate._estimate_symbolic_region_steps(
            "RegisterSubstitution",
            {
                "start_address": 4198416,
                "end_address": 4198418,
                "original_disasm": "mov eax, ebx",
                "mutated_disasm": "mov ecx, ebx",
            },
        )
        == _EXPECTED_MANAGER_SYMBOLIC_VALIDATOR_SCOPE_GATE_ESTIMAT_2
    )
    expect(
        manager._symbolic_validator._scope_gate._estimate_symbolic_region_steps(
            "NopInsertion", {"start_address": 4198432, "end_address": 4198441}
        )
        == _EXPECTED_MANAGER_SYMBOLIC_VALIDATOR_SCOPE_GATE_ESTIMAT_3
    )


def test_symbolic_binary_region_metadata_is_attached_to_mutations():
    manager = ValidationManager(mode="symbolic")
    pass_result = {
        "pass_name": "NopInsertion",
        "mutations": [
            {
                "start_address": 0x401010,
                "end_address": 0x401012,
                "metadata": {},
            }
        ],
    }
    metadata = {
        "symbolic_requested": True,
        "symbolic_status": "real-binary-observables-match",
        "symbolic_reason": "bounded real-binary symbolic effects matched for the mutated regions",
        "symbolic_binary_regions": [
            {
                "start_address": 0x401010,
                "end_address": 0x401012,
                "step_budget": 2,
                "region_exit_budget": 4,
                "step_strategy": "region-exit",
                "original_region_exit_steps": 1,
                "mutated_region_exit_steps": 3,
                "original_region_exit_address": 0x401013,
                "mutated_region_exit_address": 0x401013,
                "original_trace_addresses": [0x401010, 0x401013],
                "mutated_trace_addresses": [0x401010, 0x401011, 0x401012, 0x401013],
                "registers_checked": ["rax", "eflags"],
                "control_flow_observables": ["region_exit_address", "region_exit_steps"],
                "original_memory_writes": [],
                "mutated_memory_writes": [],
                "original_memory_write_count": 0,
                "mutated_memory_write_count": 0,
                "mismatches": [],
            }
        ],
    }

    manager._symbolic_validator._mutation_annotator._annotate_mutations_with_symbolic_metadata(pass_result, metadata)
    mutation_metadata = pass_result["mutations"][0]["metadata"]
    expect(
        mutation_metadata["symbolic_binary_region_exit_budget"]
        == _EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_REGION_EXIT_4
    )
    expect(mutation_metadata["symbolic_binary_original_region_exit_steps"] == 1)
    expect(
        mutation_metadata["symbolic_binary_mutated_region_exit_steps"]
        == _EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_MUTATED_REG_3
    )
    expect(
        mutation_metadata["symbolic_binary_original_region_exit_address"]
        == _EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_ORIGINAL_RE_4198419
    )
    expect(
        mutation_metadata["symbolic_binary_mutated_region_exit_address"]
        == _EXPECTED_MUTATION_METADATA_SYMBOLIC_BINARY_MUTATED_REG_4198419
    )
    expect(mutation_metadata["symbolic_binary_original_trace_addresses"] == [4198416, 4198419])
    expect(mutation_metadata["symbolic_binary_mutated_trace_addresses"] == [4198416, 4198417, 4198418, 4198419])
    expect(
        mutation_metadata["symbolic_binary_control_flow_observables"] == ["region_exit_address", "region_exit_steps"]
    )
    expect(mutation_metadata["symbolic_binary_original_memory_write_count"] == 0)
    expect(mutation_metadata["symbolic_binary_mutated_memory_write_count"] == 0)


def test_build_evidence_summary_for_pass_compacts_symbolic_and_structural_signal():
    summary = _build_evidence_summary_for_pass(
        "NopInsertion",
        {
            "status": "applied",
            "rolled_back": False,
            "mutations": [
                {
                    "start_address": 0x401010,
                    "end_address": 0x401012,
                    "metadata": {
                        "symbolic_binary_check_performed": True,
                        "symbolic_binary_equivalent": True,
                        "symbolic_binary_mismatches": [],
                        "symbolic_binary_step_strategy": "region-exit",
                        "symbolic_binary_original_region_exit_steps": 1,
                        "symbolic_binary_mutated_region_exit_steps": 3,
                        "symbolic_binary_control_flow_observables": [
                            "region_exit_address",
                            "region_exit_steps",
                        ],
                        "symbolic_binary_original_trace_addresses": [0x401010, 0x401013],
                        "symbolic_binary_mutated_trace_addresses": [
                            0x401010,
                            0x401011,
                            0x401012,
                            0x401013,
                        ],
                        "symbolic_binary_original_memory_write_count": 0,
                        "symbolic_binary_mutated_memory_write_count": 0,
                    },
                }
            ],
            "diff_summary": {
                "changed_regions": [(0x401010, 0x401012)],
                "changed_bytes": 3,
                "structural_regions": [{"function_address": 0x401000, "issue_count": 0}],
                "structural_issue_count": 0,
            },
        },
    )

    expect(summary[MUTATION_NAME_KEY] == "NopInsertion")
    expect(summary["changed_region_count"] == 1)
    expect(summary["symbolic_binary_regions_checked"] == 1)
    expect(summary["symbolic_binary_matched_regions"] == 1)
    expect(summary["symbolic_binary_mismatched_regions"] == 0)
    expect(summary["control_flow_observables"] == ["region_exit_address", "region_exit_steps"])
    expect(summary["max_original_trace_length"] == _EXPECTED_SUMMARY_MAX_ORIGINAL_TRACE_LENGTH_2)
    expect(summary["max_mutated_trace_length"] == _EXPECTED_SUMMARY_MAX_MUTATED_TRACE_LENGTH_4)
    expect(summary["symbolic_regions"][0]["step_strategy"] == "region-exit")


def test_summarize_pass_evidence_orders_mismatch_first():
    rows = _summarize_pass_evidence(
        {
            "RegisterSubstitution": {
                "evidence_summary": {
                    "changed_region_count": 2,
                    "structural_issue_count": 0,
                    "symbolic_binary_regions_checked": 2,
                    "symbolic_binary_mismatched_regions": 2,
                    "rolled_back": False,
                    "status": "applied",
                }
            },
            "NopInsertion": {
                "evidence_summary": {
                    "changed_region_count": 1,
                    "structural_issue_count": 0,
                    "symbolic_binary_regions_checked": 1,
                    "symbolic_binary_mismatched_regions": 0,
                    "rolled_back": False,
                    "status": "applied",
                }
            },
        }
    )

    expect(rows[0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(rows[1][MUTATION_NAME_KEY] == "NopInsertion")


def test_symbolic_validation_reports_unsupported_scope_metadata():
    manager = ValidationManager(mode="symbolic")
    binary = _FakeBinary()

    outcome = manager.validate_pass(
        binary,
        {
            "pass_name": "ExperimentalPass",
            "mutations": [
                {
                    "pass_name": "ExperimentalPass",
                    "function_address": 0x401000,
                    "start_address": 0x401010,
                    "end_address": 0x401011,
                    "mutated_bytes": "9191",
                    "metadata": {"structural_baseline": {}},
                }
            ],
        },
    )

    expect(not (outcome.metadata["symbolic_requested"] is not True))
    expect(not (outcome.metadata["symbolic_proven"] is not False))
    expect(outcome.metadata["symbolic_status"] == "unsupported-pass")


def test_build_pass_validation_context_assigns_role():
    trigger_context = _build_pass_validation_context(
        "RegisterSubstitution",
        requested_mode="symbolic",
        effective_mode="runtime",
        validation_policy={
            "policy": "degrade-runtime",
            "reason": "limited-symbolic-support",
            "limited_passes": [{"pass_name": "RegisterSubstitution", "confidence": "limited"}],
        },
    )
    expect(trigger_context["role"] == "degradation-trigger")

    degraded_context = _build_pass_validation_context(
        "NopInsertion",
        requested_mode="symbolic",
        effective_mode="runtime",
        validation_policy={
            "policy": "degrade-runtime",
            "reason": "limited-symbolic-support",
            "limited_passes": [{"pass_name": "RegisterSubstitution", "confidence": "limited"}],
        },
    )
    expect(degraded_context["role"] == "executed-under-degraded-mode")

    normal_context = _build_pass_validation_context(
        "InstructionSubstitution",
        requested_mode="structural",
        effective_mode="structural",
        validation_policy=None,
    )
    expect(normal_context["role"] == "requested-mode")


def test_enrich_validation_policy_copies_role_from_pass_results():
    enriched = _enrich_validation_policy(
        {
            "policy": "degrade-runtime",
            "limited_passes": [{"pass_name": "RegisterSubstitution", "confidence": "limited"}],
        },
        {"RegisterSubstitution": {"validation_context": {"role": "degradation-trigger"}}},
    )

    expect(enriched is not None)
    expect(enriched["limited_passes"][0]["role"] == "degradation-trigger")


def test_summarize_degradation_roles_counts_roles():
    counts = _summarize_degradation_roles(
        {
            "RegisterSubstitution": {"validation_context": {"role": "degradation-trigger"}},
            "NopInsertion": {"validation_context": {"role": "executed-under-degraded-mode"}},
            "InstructionSubstitution": {"validation_context": {"role": "requested-mode"}},
        }
    )

    expect(counts == {"degradation-trigger": 1, "executed-under-degraded-mode": 1, "requested-mode": 1})


def test_summarize_symbolic_issue_passes_orders_by_severity():
    issues = _summarize_symbolic_issue_passes(
        [
            {
                "pass_name": "BlockReordering",
                "metadata": {
                    "symbolic_requested": True,
                    "symbolic_status": "unsupported-pass",
                },
            },
            {
                "pass_name": "InstructionSubstitution",
                "metadata": {
                    "symbolic_requested": True,
                    "symbolic_observable_check_performed": True,
                    "symbolic_observable_equivalent": False,
                },
            },
            {
                "pass_name": "NopInsertion",
                "metadata": {
                    "symbolic_requested": True,
                    "symbolic_status": "bounded-step-passed",
                },
            },
        ]
    )

    expect(issues[0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(issues[0]["severity"] == "mismatch")
    expect(issues[1][MUTATION_NAME_KEY] == "BlockReordering")
    expect(issues[1]["severity"] == "without-coverage")
    expect(issues[2][MUTATION_NAME_KEY] == "NopInsertion")
    expect(issues[2]["severity"] == "bounded-only")


def test_summarize_symbolic_coverage_by_pass_counts_outcomes():
    rows = _summarize_symbolic_coverage_by_pass(
        [
            {
                "pass_name": "InstructionSubstitution",
                "metadata": {
                    "symbolic_requested": True,
                    "symbolic_observable_check_performed": True,
                    "symbolic_observable_equivalent": True,
                },
            },
            {
                "pass_name": "InstructionSubstitution",
                "metadata": {
                    "symbolic_requested": True,
                    "symbolic_observable_check_performed": True,
                    "symbolic_observable_equivalent": False,
                },
            },
            {
                "pass_name": "NopInsertion",
                "metadata": {
                    "symbolic_requested": True,
                    "symbolic_status": "bounded-step-passed",
                },
            },
        ]
    )

    expect(rows[0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(rows[0]["symbolic_requested"] == _EXPECTED_ROWS_0_SYMBOLIC_REQUESTED_2)
    expect(rows[0]["observable_match"] == 1)
    expect(rows[0]["observable_mismatch"] == 1)
    expect(rows[1][MUTATION_NAME_KEY] == "NopInsertion")
    expect(rows[1]["bounded_only"] == 1)


def test_build_symbolic_summary_for_pass_includes_issues():
    summary = _build_symbolic_summary_for_pass(
        "InstructionSubstitution",
        [
            {
                "pass_name": "InstructionSubstitution",
                "metadata": {
                    "symbolic_requested": True,
                    "symbolic_observable_check_performed": True,
                    "symbolic_observable_equivalent": False,
                },
            },
            {
                "pass_name": "NopInsertion",
                "metadata": {
                    "symbolic_requested": True,
                    "symbolic_status": "bounded-step-passed",
                },
            },
        ],
    )

    expect(summary[MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(summary["severity"] == "mismatch")
    expect(summary["issue_count"] == 1)
    expect(summary["symbolic_requested"] == 1)
    expect(summary["observable_mismatch"] == 1)
    expect(summary["issues"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(summary["issues"][0]["severity"] == "mismatch")


def test_build_symbolic_summary_for_pass_marks_clean_and_not_requested():
    clean_summary = _build_symbolic_summary_for_pass(
        "InstructionSubstitution",
        [
            {
                "pass_name": "InstructionSubstitution",
                "metadata": {
                    "symbolic_requested": True,
                    "symbolic_observable_check_performed": True,
                    "symbolic_observable_equivalent": True,
                },
            }
        ],
    )

    expect(clean_summary["severity"] == "clean")
    expect(clean_summary["issue_count"] == 0)

    missing_summary = _build_symbolic_summary_for_pass("NopInsertion", [])

    expect(missing_summary["severity"] == "not-requested")
    expect(missing_summary["issue_count"] == 0)


def test_summarize_symbolic_severity_by_pass_orders_rows():
    rows = _summarize_symbolic_severity_by_pass(
        {
            "RegisterSubstitution": {
                "symbolic_summary": {
                    "severity": "bounded-only",
                    "issue_count": 1,
                    "symbolic_requested": 1,
                }
            },
            "InstructionSubstitution": {
                "symbolic_summary": {
                    "severity": "mismatch",
                    "issue_count": 2,
                    "symbolic_requested": 2,
                }
            },
            "NopInsertion": {
                "symbolic_summary": {
                    "severity": "clean",
                    "issue_count": 0,
                    "symbolic_requested": 1,
                }
            },
        }
    )

    expect(rows[0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(rows[0]["severity"] == "mismatch")
    expect(rows[1][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(rows[1]["severity"] == "bounded-only")
    expect(rows[2][MUTATION_NAME_KEY] == "NopInsertion")
    expect(rows[2]["severity"] == "clean")


def test_symbolic_validation_reports_bounded_step_metadata():
    symbolic_validator = importlib.import_module("r2morph.validation.symbolic_validator").SymbolicValidator
    load_symbolic_bridge = importlib.import_module("tests._doubles.symbolic_validation_doubles").load_symbolic_bridge

    manager = ValidationManager(
        mode="symbolic",
        symbolic_validator=symbolic_validator(bridge_module_loader=load_symbolic_bridge),
    )
    binary = _FakeBinary()

    outcome = manager.validate_pass(
        binary,
        {
            "pass_name": "InstructionSubstitution",
            "mutations": [
                {
                    "pass_name": "InstructionSubstitution",
                    "function_address": 0x401000,
                    "start_address": 0x401010,
                    "end_address": 0x401011,
                    "mutated_bytes": "9191",
                    "metadata": {"structural_baseline": {}},
                }
            ],
        },
    )

    expect(outcome.metadata["symbolic_status"] == "bounded-step-passed")
    expect(outcome.metadata["symbolic_step_count"] == 1)
    expect(outcome.metadata["symbolic_flat_successors"] == 1)
    expect(outcome.metadata["symbolic_unsat_successors"] == 0)
    expect(
        outcome.metadata["symbolic_stepped_regions"]
        == [
            {
                "start_address": 4198416,
                "end_address": 4198417,
                "flat_successors": 1,
                "unsat_successors": 0,
                "successor_addresses": [4198417],
                "step_budget": 1,
            }
        ]
    )


def test_symbolic_pipeline_marks_known_instruction_equivalence_as_supported():
    symbolic_validator = importlib.import_module("r2morph.validation.symbolic_validator").SymbolicValidator
    load_symbolic_bridge = importlib.import_module("tests._doubles.symbolic_validation_doubles").load_symbolic_bridge

    pipeline = Pipeline()
    pipeline.add_pass(_InstructionSubstitutionSemanticPass())

    result = pipeline.run(
        _FakeBinary(),
        PipelineRunOptions(
            session=_FakeSession(),
            validation_manager=ValidationManager(
                mode="symbolic",
                symbolic_validator=symbolic_validator(bridge_module_loader=load_symbolic_bridge),
            ),
        ),
    )

    symbolic = result["validation"]["symbolic"]
    expect(not (symbolic["requested"] is not True))
    expect(symbolic["supported_passes"] == ["InstructionSubstitution"])
    expect(symbolic["fallback_passes"] == [])
    expect(symbolic["statuses"][0]["status"] == "bounded-step-known-equivalence")


def test_symbolic_pipeline_marks_observable_match_as_supported():
    symbolic_validator = importlib.import_module("r2morph.validation.symbolic_validator").SymbolicValidator
    observable_match_shellcode_checker = importlib.import_module(
        "tests._doubles.symbolic_validation_doubles"
    ).ObservableMatchShellcodeChecker
    load_symbolic_bridge = importlib.import_module("tests._doubles.symbolic_validation_doubles").load_symbolic_bridge

    pipeline = Pipeline()
    pipeline.add_pass(_InstructionSubstitutionSemanticPass())

    result = pipeline.run(
        _FakeBinary(),
        PipelineRunOptions(
            session=_FakeSession(),
            validation_manager=ValidationManager(
                mode="symbolic",
                symbolic_validator=symbolic_validator(
                    bridge_module_loader=load_symbolic_bridge,
                    shellcode_checker=observable_match_shellcode_checker(),
                ),
            ),
        ),
    )

    symbolic = result["validation"]["symbolic"]
    expect(not (symbolic["requested"] is not True))
    expect(symbolic["supported_passes"] == ["InstructionSubstitution"])
    expect(symbolic["fallback_passes"] == [])
    expect(symbolic["statuses"][0]["status"] == "bounded-step-observables-match")
    mutation = result["mutations"][0]
    expect(not (mutation["metadata"]["symbolic_requested"] is not True))
    expect(mutation["metadata"]["symbolic_status"] == "bounded-step-observables-match")
    expect(not (mutation["metadata"]["symbolic_observable_check_performed"] is not True))
    expect(not (mutation["metadata"]["symbolic_observable_equivalent"] is not True))
    expect(mutation["metadata"]["symbolic_observables_checked"] == ["eax", "eflags"])


def test_engine_build_report_uses_stable_sections():
    engine = MorphEngine(config={"mode": "test"})
    report = engine.build_report(
        {
            "input_path": "in.bin",
            "working_path": "work.bin",
            "arch": "x86",
            "bits": 64,
            "format": "ELF",
            "functions": 12,
            "pass_results": {"RecordingPass": {"mutations_applied": 1}},
            "mutations": [{"pass_name": "RecordingPass"}],
            "validation": {"all_passed": True},
            "passes_run": 1,
            "total_mutations": 1,
            "rolled_back_passes": 1,
            "failed_passes": 0,
            "discarded_mutations": 1,
            "validation_mode": "structural",
            "execution_time_seconds": 0.1,
            "config": {"mode": "test"},
        }
    )

    expect_all(
        report["input"]["path"] == "in.bin",
        report["output"]["working_path"] == "work.bin",
        report["summary"]["total_mutations"] == 1,
        report["summary"]["rolled_back_passes"] == 1,
        report["summary"]["discarded_mutations"] == 1,
        report["summary"]["symbolic_issue_passes"] == [],
        report["summary"]["symbolic_coverage_by_pass"] == [],
        report["summary"]["symbolic_severity_by_pass"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["summary"]["symbolic_severity_by_pass"][0]["severity"] == "not-requested",
        report["summary"]["symbolic_issue_map"] == {},
        report["summary"]["symbolic_coverage_map"] == {},
        report["summary"]["symbolic_severity_map"]["RecordingPass"][MUTATION_NAME_KEY] == "RecordingPass",
        report["summary"]["symbolic_status_counts"] == {},
        report["summary"]["symbolic_status_rows"] == [],
        report["summary"]["symbolic_status_map"] == {},
        report["summary"]["symbolic_overview"]["symbolic_requested"] == 0,
        report["summary"]["observable_mismatch_by_pass"] == [],
        report["summary"]["observable_mismatch_map"] == {},
        report["summary"]["observable_mismatch_priority"] == [],
        report["summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["summary"]["pass_evidence_priority"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["summary"]["pass_coverage_buckets"]["uncovered"] == ["RecordingPass"],
        report["summary"]["pass_risk_buckets"]["clean"] == ["RecordingPass"],
        report["summary"]["pass_symbolic_summary"]["RecordingPass"]["severity"] == "not-requested",
        report["summary"]["pass_capabilities"]["RecordingPass"] == {},
        report["summary"]["pass_capability_summary"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["summary"]["pass_capability_summary_map"]["RecordingPass"][MUTATION_NAME_KEY] == "RecordingPass",
        report["summary"]["validation_role_rows"] == [],
        report["summary"]["validation_role_map"] == {},
        not (report["summary"]["validation_adjustments"]["degraded_validation"] is not False),
        report["summary"]["pass_evidence_map"]["RecordingPass"][MUTATION_NAME_KEY] == "RecordingPass",
        report["summary"]["pass_triage_rows"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["summary"]["pass_triage_map"]["RecordingPass"][MUTATION_NAME_KEY] == "RecordingPass",
        report["summary"]["pass_evidence_compact"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["summary"]["discarded_mutation_summary"]["by_pass"] == [],
        report["summary"]["discarded_mutation_priority"] == [],
        report["passes"]["RecordingPass"]["evidence_summary"][MUTATION_NAME_KEY] == "RecordingPass",
        report["pass_evidence"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["pass_evidence_priority"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["pass_coverage_buckets"]["uncovered"] == ["RecordingPass"],
        report["pass_risk_buckets"]["clean"] == ["RecordingPass"],
        report["pass_symbolic_summary"]["RecordingPass"]["severity"] == "not-requested",
        report["symbolic_issue_map"] == {},
        report["symbolic_coverage_map"] == {},
        report["symbolic_severity_map"]["RecordingPass"][MUTATION_NAME_KEY] == "RecordingPass",
        report["symbolic_status_counts"] == {},
        report["symbolic_status_rows"] == [],
        report["symbolic_status_map"] == {},
        report["symbolic_overview"]["symbolic_requested"] == 0,
        report["observable_mismatch_by_pass"] == [],
        report["observable_mismatch_map"] == {},
        report["observable_mismatch_priority"] == [],
        report["pass_capabilities"]["RecordingPass"] == {},
        report["pass_capability_summary"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["pass_capability_summary_map"]["RecordingPass"][MUTATION_NAME_KEY] == "RecordingPass",
        report["validation_role_rows"] == [],
        report["validation_role_map"] == {},
        not (report["validation_adjustments"]["degraded_validation"] is not False),
        report["pass_evidence_map"]["RecordingPass"][MUTATION_NAME_KEY] == "RecordingPass",
        report["pass_region_evidence_map"] == {},
        report["pass_triage_rows"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["pass_triage_map"]["RecordingPass"][MUTATION_NAME_KEY] == "RecordingPass",
        report["pass_evidence_compact"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["normalized_pass_results"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["report_views"]["passes"]["uncovered"] == ["RecordingPass"],
        report["report_views"]["general_passes"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["report_views"]["general_passes"][0]["region_evidence_count"] == 0,
        report["report_views"]["general_pass_rows"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["report_views"]["general_pass_rows"][0]["gate_failure_count"] == 0,
        report["report_views"]["general_pass_rows"][0]["discarded_count"] == 0,
        report["report_views"]["general_filter_views"]
        == {
            "risky": [],
            "structural_risk": [],
            "symbolic_risk": [],
            "clean": ["RecordingPass"],
            "covered": [],
            "uncovered": ["RecordingPass"],
        },
        report["report_views"]["general_triage_rows"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["report_views"]["general_summary"]
        == {
            "pass_count": 1,
            "passes": ["RecordingPass"],
            "risky_pass_count": 0,
            "clean_pass_count": 1,
            "covered_pass_count": 0,
            "uncovered_pass_count": 1,
        },
        report["report_views"]["general_summary_rows"][0]["section"] == "passes",
        report["report_views"]["general_renderer_state"]["summary"]["pass_count"] == 1,
        report["report_views"]["general_renderer_state"]["general_summary"]["pass_count"] == 1,
        report["report_views"]["general_renderer_state"]["summary_rows"][0]["section"] == "passes",
        report["report_views"]["general_renderer_state"]["general_summary_rows"][0]["section"] == "passes",
        report["report_views"]["general_renderer_state"]["symbolic"]
        == {
            "symbolic_requested": 0,
            "observable_match": 0,
            "observable_mismatch": 0,
            "bounded_only": 0,
            "without_coverage": 0,
        },
        report["report_views"]["general_renderer_state"]["general_symbolic"]
        == {
            "symbolic_requested": 0,
            "observable_match": 0,
            "observable_mismatch": 0,
            "bounded_only": 0,
            "without_coverage": 0,
        },
        report["report_views"]["general_renderer_state"]["general_gates"]
        == {
            "failed": False,
            "failure_count": 0,
            "pass_count": 0,
            "expected_severity_counts": {},
            "severity_priority": [],
            "passes": [],
        },
        report["report_views"]["general_renderer_state"]["general_degradation"]
        == {
            "requested_validation_mode": None,
            "effective_validation_mode": None,
            "degraded_validation": False,
            "row_count": 0,
            "passes": [],
            "gate_failure_count": 0,
        },
        report["report_views"]["general_renderer_state"]["general_discards"]
        == {"count": 0, "passes": [], "reasons": {}, "impacts": {"high": 0, "medium": 0, "low": 0}},
        report["report_views"]["general_renderer_state"]["filter_views"]
        == {
            "risky": [],
            "structural_risk": [],
            "symbolic_risk": [],
            "clean": ["RecordingPass"],
            "covered": [],
            "uncovered": ["RecordingPass"],
        },
        report["report_views"]["general_renderer_state"]["general_filter_views"]
        == {
            "risky": [],
            "structural_risk": [],
            "symbolic_risk": [],
            "clean": ["RecordingPass"],
            "covered": [],
            "uncovered": ["RecordingPass"],
        },
        report["report_views"]["general_renderer_state"]["pass_rows"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["report_views"]["general_renderer_state"]["general_passes"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["report_views"]["general_renderer_state"]["general_pass_rows"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["report_views"]["general_renderer_state"]["general_triage_rows"][0][MUTATION_NAME_KEY]
        == "RecordingPass",
        report["report_views"]["general_symbolic"]["overview"]
        == {
            "symbolic_requested": 0,
            "observable_match": 0,
            "observable_mismatch": 0,
            "bounded_only": 0,
            "without_coverage": 0,
        },
        report["report_views"]["general_gates"]["summary"] == {},
        report["report_views"]["general_degradation"]["summary"]
        == {
            "requested_validation_mode": None,
            "effective_validation_mode": None,
            "degraded_validation": False,
            "row_count": 0,
            "passes": [],
            "gate_failure_count": 0,
        },
        report["report_views"]["general_discards"]["summary"]
        == {"count": 0, "passes": [], "reasons": {}, "impacts": {"high": 0, "medium": 0, "low": 0}},
        report["report_views"]["triage_priority"][0][MUTATION_NAME_KEY] == "RecordingPass",
        report["report_views"][ONLY_MUTATION_KEY]["RecordingPass"]["normalized"][MUTATION_NAME_KEY] == "RecordingPass",
        report["report_views"][ONLY_MUTATION_KEY]["RecordingPass"]["region_evidence"] == [],
        report["report_views"]["pass_filter_views"]["only_clean_passes"] == ["RecordingPass"],
        report["report_views"]["mismatch_view"] == [],
        report["report_views"]["only_mismatches"]["priority"] == [],
        report["report_views"]["only_mismatches"]["rows"] == [],
        report["report_views"]["only_mismatches"]["compact_rows"] == [],
        report["report_views"]["only_mismatches"]["final_rows"] == [],
        report["report_views"]["only_mismatches"]["final_by_pass"] == {},
        report["report_views"]["only_mismatches"]["compact_by_pass"] == {},
        report["report_views"]["only_mismatches"]["compact_summary"]
        == {
            "pass_count": 0,
            "mismatch_count": 0,
            "degraded_pass_count": 0,
            "region_count": 0,
            "region_mismatch_count": 0,
            "region_exit_match_count": 0,
            "passes": [],
        },
        report["report_views"]["only_mismatches"]["summary"]
        == {
            "pass_count": 0,
            "mismatch_count": 0,
            "degraded_pass_count": 0,
            "trigger_pass_count": 0,
            "region_count": 0,
            "region_mismatch_count": 0,
            "region_exit_match_count": 0,
            "passes": [],
        },
        report["report_views"]["only_failed_gates"]["priority"] == [],
        report["report_views"]["only_failed_gates"]["severity_priority"] == [],
        report["report_views"]["only_failed_gates"]["grouped_by_pass"] == [],
        report["report_views"]["only_failed_gates"]["compact_rows"] == [],
        report["report_views"]["only_failed_gates"]["final_rows"] == [],
        report["report_views"]["only_failed_gates"]["final_by_pass"] == {},
        report["report_views"]["only_failed_gates"]["compact_by_pass"] == {},
        report["report_views"]["only_failed_gates"]["expected_severity_counts"] == {},
        not (report["report_views"]["only_failed_gates"]["failed"] is not False),
        report["report_views"]["only_failed_gates"]["failure_count"] == 0,
        report["report_views"]["only_failed_gates"]["pass_count"] == 0,
        report["report_views"]["only_failed_gates"]["passes"] == [],
        report["report_views"]["only_failed_gates"]["compact_summary"]
        == {
            "failed": False,
            "failure_count": 0,
            "pass_count": 0,
            "expected_severity_counts": {},
            "severity_priority": [],
            "passes": [],
        },
        report["report_views"]["validation_adjustments"]["rows"] == [],
        report["report_views"]["validation_adjustments"]["compact_rows"] == [],
        report["report_views"]["validation_adjustments"]["compact_by_pass"] == {},
        report["report_views"]["validation_adjustments"]["summary"]
        == {
            "requested_validation_mode": None,
            "effective_validation_mode": None,
            "row_count": 0,
            "trigger_count": 0,
            "degraded_execution_count": 0,
            "degraded_validation": False,
            "gate_failure_count": 0,
            "passes": [],
        },
        report["report_views"]["validation_adjustments"]["compact_summary"]
        == {
            "degraded_validation": False,
            "row_count": 0,
            "trigger_count": 0,
            "degraded_execution_count": 0,
            "gate_failure_count": 0,
            "passes": [],
        },
        report["report_views"]["discarded_view"]["by_reason"] == {},
        report["report_views"]["discarded_view"]["compact_by_reason"] == {},
        report["report_views"]["discarded_view"]["rows"] == [],
        report["report_views"]["discarded_view"]["compact_rows"] == [],
        report["report_views"]["discarded_view"]["final_rows"] == [],
        report["report_views"]["discarded_view"]["final_by_pass"] == {},
        report["report_views"]["discarded_view"]["compact_by_pass"] == {},
        report["report_views"]["discarded_view"]["by_impact"] == {"high": [], "medium": [], "low": []},
        report["report_views"]["discarded_view"]["summary"]
        == {"count": 0, "passes": [], "reasons": [], "impacts": {"high": 0, "medium": 0, "low": 0}},
        report["report_views"]["discarded_view"]["compact_summary"]
        == {
            "count": 0,
            "pass_count": 0,
            "reason_count": 0,
            "impact_counts": {"high": 0, "medium": 0, "low": 0},
            "passes": [],
        },
        report["schema_version"] == 1,
        report["summary"]["schema_version"] == 1,
        report["validation_adjustment_rows"] == [],
        report["discarded_mutation_summary"]["by_pass"] == [],
        report["discarded_mutation_priority"] == [],
        report["passes"]["RecordingPass"]["symbolic_summary"]["symbolic_requested"] == 0,
        report["passes"]["RecordingPass"]["symbolic_summary"]["severity"] == "not-requested",
    )


def test_build_pass_region_evidence_map_marks_region_exit_equivalence() -> None:
    pass_results = {
        "ExamplePass": {
            "evidence_summary": {
                "symbolic_regions": [
                    {
                        "start_address": 0x401000,
                        "end_address": 0x401002,
                        "equivalent": True,
                        "mismatch_count": 0,
                        "mismatches": [],
                        "step_strategy": "region-exit",
                        "original_region_exit_address": 0x401010,
                        "mutated_region_exit_address": 0x401010,
                        "original_trace_length": 2,
                        "mutated_trace_length": 2,
                        "original_region_exit_steps": 2,
                        "mutated_region_exit_steps": 2,
                    },
                    {
                        "start_address": 0x401020,
                        "end_address": 0x401022,
                        "equivalent": False,
                        "mismatch_count": 1,
                        "mismatches": ["rax"],
                        "step_strategy": "region-exit",
                        "original_region_exit_address": 0x401030,
                        "mutated_region_exit_address": 0x401031,
                        "original_trace_length": 3,
                        "mutated_trace_length": 4,
                        "original_region_exit_steps": 3,
                        "mutated_region_exit_steps": 4,
                    },
                ]
            }
        }
    }

    region_map = _build_pass_region_evidence_map(pass_results)

    expect(not (region_map["ExamplePass"][0]["region_exit_equivalent"] is not True))
    expect(not (region_map["ExamplePass"][1]["region_exit_equivalent"] is not False))


def test_engine_build_report_persists_pass_summary_maps():
    engine = MorphEngine(config={"requested_validation_mode": "symbolic"})
    report = engine.build_report(
        {
            "input_path": "in.bin",
            "working_path": "work.bin",
            "arch": "x86",
            "bits": 64,
            "format": "ELF",
            "functions": 1,
            "pass_results": {
                "RecordingPass": {
                    "mutations_applied": 1,
                    "validation_context": {
                        "requested_validation_mode": "symbolic",
                        "effective_validation_mode": "runtime",
                        "degraded_execution": True,
                        "degradation_triggered_by_pass": True,
                        "role": "degradation-trigger",
                    },
                }
            },
            "mutations": [{"pass_name": "RecordingPass"}],
            "validation": {"all_passed": True},
            "validation_mode": "runtime",
        }
    )

    expect(report["pass_symbolic_summary"]["RecordingPass"][MUTATION_NAME_KEY] == "RecordingPass")
    expect(report["summary"]["pass_symbolic_summary"]["RecordingPass"][MUTATION_NAME_KEY] == "RecordingPass")
    expect(report["pass_validation_context"]["RecordingPass"]["role"] == "degradation-trigger")
    expect(report["summary"]["pass_validation_context"]["RecordingPass"]["role"] == "degradation-trigger")


def test_summarize_pass_buckets_distinguishes_risk_and_coverage():
    pass_results = {
        "InstructionSubstitution": {
            "symbolic_summary": {
                "severity": "clean",
                "issue_count": 0,
                "symbolic_requested": 1,
                "without_coverage": 0,
            },
            "evidence_summary": {
                "structural_issue_count": 0,
                "symbolic_binary_mismatched_regions": 0,
                "symbolic_binary_regions_checked": 1,
            },
        },
        "RegisterSubstitution": {
            "symbolic_summary": {
                "severity": "mismatch",
                "issue_count": 1,
                "symbolic_requested": 1,
                "without_coverage": 0,
            },
            "evidence_summary": {
                "structural_issue_count": 0,
                "symbolic_binary_mismatched_regions": 1,
                "symbolic_binary_regions_checked": 1,
            },
        },
        "ReportFixture": {
            "symbolic_summary": {
                "severity": "not-requested",
                "issue_count": 0,
                "symbolic_requested": 0,
                "without_coverage": 0,
            },
            "evidence_summary": {
                "structural_issue_count": 0,
                "symbolic_binary_mismatched_regions": 0,
                "symbolic_binary_regions_checked": 0,
            },
        },
    }

    coverage = _summarize_pass_coverage_buckets(pass_results)
    risk = _summarize_pass_risk_buckets(pass_results)

    expect(coverage["covered"] == ["InstructionSubstitution"])
    expect(coverage["uncovered"] == ["ReportFixture"])
    expect(sorted(coverage["clean_only"]) == ["InstructionSubstitution", "ReportFixture"])
    expect(risk["risky"] == ["RegisterSubstitution"])
    expect(risk["symbolic"] == ["RegisterSubstitution"])
    expect(sorted(risk["clean"]) == ["InstructionSubstitution", "ReportFixture"])
    expect(risk["covered"] == ["InstructionSubstitution"])
    expect(risk["uncovered"] == ["ReportFixture"])
