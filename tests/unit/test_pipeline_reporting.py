from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from r2morph.core.engine import (
    MorphEngine,
    _build_pass_region_evidence_map,
    _build_pass_validation_context,
    _build_gate_failure_priority,
    _build_gate_failure_severity_priority,
    _summarize_structural_evidence,
    _summarize_diff_digest,
    _summarize_gate_failures,
    _summarize_pass_timings,
    _build_symbolic_summary_for_pass,
    _build_evidence_summary_for_pass,
    _summarize_pass_evidence,
    _summarize_symbolic_severity_by_pass,
    _enrich_validation_policy,
    _summarize_symbolic_coverage_by_pass,
    _summarize_symbolic_issue_passes,
    _summarize_degradation_roles,
    _summarize_pass_coverage_buckets,
    _summarize_pass_risk_buckets,
)
from r2morph.core.support import classify_target_support
from r2morph.mutations.base import MutationPass
from r2morph.pipeline import Pipeline
from r2morph.validation.manager import ValidationIssue, ValidationManager, ValidationOutcome


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
        self._checkpoint_objects.append(SimpleNamespace(name=name, binary_path=Path("/tmp/fake.bin")))

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
        session=_FakeSession(),
        validation_manager=_FakeValidationManager(passed=True),
    )

    assert result["total_mutations"] == 1
    assert len(result["mutations"]) == 1
    assert result["mutations"][0]["pass_name"] == "RecordingPass"
    assert result["validation"]["all_passed"] is True
    assert result["pass_results"]["RecordingPass"]["diff_summary"]["changed_bytes"] == 2
    assert result["pass_results"]["RecordingPass"]["diff_summary"]["region_details"] == [
        {
            "address_range": [0x401010, 0x401011],
            "mutation_kind": "instruction_substitution",
            "byte_diff_count": 2,
            "function_address": 0x401000,
        }
    ]
    assert result["pass_results"]["RecordingPass"]["diff_summary"]["structural_issue_count"] == 0


def test_classify_target_support_reports_stable_and_prolonged_experimental():
    stable = classify_target_support("ELF", "x86_64")
    macho = classify_target_support("Mach-O", "arm64")
    pe = classify_target_support("PE", "x86_64")
    compat = classify_target_support("ELF", "x86", 64)
    unknown = classify_target_support("flat", "mips")

    assert stable["tier"] == "stable"
    assert compat["tier"] == "stable"
    assert compat["architecture"] == "x86_64"
    assert macho["tier"] == "prolonged-experimental"
    assert pe["tier"] == "prolonged-experimental"
    assert unknown["tier"] == "unsupported"


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

    assert timings[0]["pass_name"] == "InstructionSubstitution"
    assert timings[0]["execution_time_seconds"] == 0.25
    assert timings[0]["validation_issue_count"] == 1
    assert timings[1]["rolled_back"] is True
    assert digest == {
        "changed_region_count": 3,
        "changed_bytes": 4,
        "mutation_kinds": ["instruction_substitution", "nop_insertion"],
        "passes_with_changes": [
            {
                "pass_name": "NopInsertion",
                "changed_region_count": 2,
                "changed_bytes": 2,
            },
            {
                "pass_name": "InstructionSubstitution",
                "changed_region_count": 1,
                "changed_bytes": 2,
            },
        ],
    }


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

    assert digest == {
        "region_count": 2,
        "validators": ["patch_integrity", "structural"],
        "severity_counts": {"error": 2, "info": 1},
        "sample_messages": [
            "invalid mutation",
            "patched bytes differ",
            "stack balanced",
        ],
    }


def test_engine_build_report_includes_gate_failure_summary():
    engine = MorphEngine()
    report = engine.build_report(
        {
            "input_path": "/tmp/original.bin",
            "working_path": "/tmp/working.bin",
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
    assert report["gate_failures"] == expected
    assert report["gate_failure_priority"] == expected_priority
    assert report["gate_failure_severity_priority"] == expected_severity_priority
    assert report["summary"]["gate_failures"] == expected
    assert report["summary"]["gate_failure_priority"] == expected_priority
    assert report["summary"]["gate_failure_severity_priority"] == expected_severity_priority
    assert report["summary"]["gate_evaluation"] == report["gate_evaluation"]["results"]
    assert report["support_profile"] == {
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
    assert report["timings"]["passes"] == []
    assert report["summary"]["pass_timing_summary"] == []
    assert report["diff_digest"] == {
        "changed_region_count": 0,
        "changed_bytes": 0,
        "mutation_kinds": [],
        "passes_with_changes": [],
    }
    assert report["structural_evidence"] == {
        "region_count": 0,
        "validators": [],
        "severity_counts": {},
        "sample_messages": [],
    }


def test_engine_build_report_includes_support_profile_timings_and_diff_digest():
    engine = MorphEngine()
    report = engine.build_report(
        {
            "input_path": "/tmp/original.bin",
            "working_path": "/tmp/working.bin",
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

    assert report["support_profile"]["tier"] == "stable"
    assert report["support_profile"]["secondary_cli_namespace"] == "experimental"
    assert report["summary"]["support_profile"]["tier"] == "stable"
    assert report["timings"]["execution_time_seconds"] == 1.25
    assert report["timings"]["passes"][0]["pass_name"] == "InstructionSubstitution"
    assert report["summary"]["pass_timing_summary"][0]["execution_time_seconds"] == 0.25
    assert report["diff_digest"]["changed_region_count"] == 1
    assert report["diff_digest"]["changed_bytes"] == 2
    assert report["summary"]["structural_regions"] == [
        {
            "address_range": [0x401010, 0x401012],
            "validators": ["structural"],
            "messages": ["ok"],
            "severities": ["info"],
        }
    ]
    assert report["structural_evidence"] == {
        "region_count": 1,
        "validators": ["structural"],
        "severity_counts": {"info": 1},
        "sample_messages": ["ok"],
    }


def test_pipeline_rolls_back_failed_pass_validation():
    session = _FakeSession()
    binary = _FakeBinary()
    pipeline = Pipeline()
    pipeline.add_pass(_RecordingPass())

    result = pipeline.run(
        binary,
        session=session,
        validation_manager=_FakeValidationManager(passed=False),
        rollback_policy="skip-invalid-pass",
    )

    assert result["total_mutations"] == 0
    assert result["rolled_back_passes"] == 1
    assert result["discarded_mutations"] == 1
    assert result["pass_results"]["RecordingPass"]["rolled_back"] is True
    assert result["pass_results"]["RecordingPass"]["rollback_reason"] == "validation_failed"
    assert result["pass_results"]["RecordingPass"]["discarded_mutations"] == 1
    assert result["mutations"] == []
    assert session.rollbacks == ["pass_1_recordingpass"]
    assert binary.reload_calls == 1
    assert result["discarded_mutations_detail"][0]["metadata"]["discard_reason"] == "validation_failed"
    assert result["pass_results"]["RecordingPass"]["diff_summary"]["structural_regions"] == [
        {
            "address_range": [0x401010, 0x401011],
            "validators": ["structural"],
            "messages": ["invalid mutation"],
            "severities": ["error"],
        }
    ]


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

    assert outcome.passed is False
    assert any(issue.validator == "patch_integrity" for issue in outcome.issues)


def test_symbolic_region_step_budget_uses_pass_kind_and_disassembly():
    manager = ValidationManager(mode="symbolic")

    assert (
        manager._estimate_symbolic_region_steps(
            "InstructionSubstitution",
            {
                "start_address": 0x401000,
                "end_address": 0x401001,
                "original_disasm": "xor eax, eax",
                "mutated_disasm": "sub eax, eax",
            },
        )
        == 1
    )
    assert (
        manager._estimate_symbolic_region_steps(
            "RegisterSubstitution",
            {
                "start_address": 0x401010,
                "end_address": 0x401012,
                "original_disasm": "mov eax, ebx",
                "mutated_disasm": "mov ecx, ebx",
            },
        )
        == 2
    )
    assert (
        manager._estimate_symbolic_region_steps(
            "NopInsertion",
            {
                "start_address": 0x401020,
                "end_address": 0x401029,
            },
        )
        == 3
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

    manager._annotate_mutations_with_symbolic_metadata(pass_result, metadata)
    mutation_metadata = pass_result["mutations"][0]["metadata"]
    assert mutation_metadata["symbolic_binary_region_exit_budget"] == 4
    assert mutation_metadata["symbolic_binary_original_region_exit_steps"] == 1
    assert mutation_metadata["symbolic_binary_mutated_region_exit_steps"] == 3
    assert mutation_metadata["symbolic_binary_original_region_exit_address"] == 0x401013
    assert mutation_metadata["symbolic_binary_mutated_region_exit_address"] == 0x401013
    assert mutation_metadata["symbolic_binary_original_trace_addresses"] == [0x401010, 0x401013]
    assert mutation_metadata["symbolic_binary_mutated_trace_addresses"] == [
        0x401010,
        0x401011,
        0x401012,
        0x401013,
    ]
    assert mutation_metadata["symbolic_binary_control_flow_observables"] == [
        "region_exit_address",
        "region_exit_steps",
    ]
    assert mutation_metadata["symbolic_binary_original_memory_write_count"] == 0
    assert mutation_metadata["symbolic_binary_mutated_memory_write_count"] == 0


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

    assert summary["pass_name"] == "NopInsertion"
    assert summary["changed_region_count"] == 1
    assert summary["symbolic_binary_regions_checked"] == 1
    assert summary["symbolic_binary_matched_regions"] == 1
    assert summary["symbolic_binary_mismatched_regions"] == 0
    assert summary["control_flow_observables"] == ["region_exit_address", "region_exit_steps"]
    assert summary["max_original_trace_length"] == 2
    assert summary["max_mutated_trace_length"] == 4
    assert summary["symbolic_regions"][0]["step_strategy"] == "region-exit"


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

    assert rows[0]["pass_name"] == "RegisterSubstitution"
    assert rows[1]["pass_name"] == "NopInsertion"


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

    assert outcome.metadata["symbolic_requested"] is True
    assert outcome.metadata["symbolic_proven"] is False
    assert outcome.metadata["symbolic_status"] == "unsupported-pass"


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
    assert trigger_context["role"] == "degradation-trigger"

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
    assert degraded_context["role"] == "executed-under-degraded-mode"

    normal_context = _build_pass_validation_context(
        "InstructionSubstitution",
        requested_mode="structural",
        effective_mode="structural",
        validation_policy=None,
    )
    assert normal_context["role"] == "requested-mode"


def test_enrich_validation_policy_copies_role_from_pass_results():
    enriched = _enrich_validation_policy(
        {
            "policy": "degrade-runtime",
            "limited_passes": [{"pass_name": "RegisterSubstitution", "confidence": "limited"}],
        },
        {"RegisterSubstitution": {"validation_context": {"role": "degradation-trigger"}}},
    )

    assert enriched is not None
    assert enriched["limited_passes"][0]["role"] == "degradation-trigger"


def test_summarize_degradation_roles_counts_roles():
    counts = _summarize_degradation_roles(
        {
            "RegisterSubstitution": {"validation_context": {"role": "degradation-trigger"}},
            "NopInsertion": {"validation_context": {"role": "executed-under-degraded-mode"}},
            "InstructionSubstitution": {"validation_context": {"role": "requested-mode"}},
        }
    )

    assert counts == {
        "degradation-trigger": 1,
        "executed-under-degraded-mode": 1,
        "requested-mode": 1,
    }


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

    assert issues[0]["pass_name"] == "InstructionSubstitution"
    assert issues[0]["severity"] == "mismatch"
    assert issues[1]["pass_name"] == "BlockReordering"
    assert issues[1]["severity"] == "without-coverage"
    assert issues[2]["pass_name"] == "NopInsertion"
    assert issues[2]["severity"] == "bounded-only"


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

    assert rows[0]["pass_name"] == "InstructionSubstitution"
    assert rows[0]["symbolic_requested"] == 2
    assert rows[0]["observable_match"] == 1
    assert rows[0]["observable_mismatch"] == 1
    assert rows[1]["pass_name"] == "NopInsertion"
    assert rows[1]["bounded_only"] == 1


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

    assert summary["pass_name"] == "InstructionSubstitution"
    assert summary["severity"] == "mismatch"
    assert summary["issue_count"] == 1
    assert summary["symbolic_requested"] == 1
    assert summary["observable_mismatch"] == 1
    assert summary["issues"][0]["pass_name"] == "InstructionSubstitution"
    assert summary["issues"][0]["severity"] == "mismatch"


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

    assert clean_summary["severity"] == "clean"
    assert clean_summary["issue_count"] == 0

    missing_summary = _build_symbolic_summary_for_pass("NopInsertion", [])

    assert missing_summary["severity"] == "not-requested"
    assert missing_summary["issue_count"] == 0


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

    assert rows[0]["pass_name"] == "InstructionSubstitution"
    assert rows[0]["severity"] == "mismatch"
    assert rows[1]["pass_name"] == "RegisterSubstitution"
    assert rows[1]["severity"] == "bounded-only"
    assert rows[2]["pass_name"] == "NopInsertion"
    assert rows[2]["severity"] == "clean"


def test_symbolic_validation_reports_bounded_step_metadata(monkeypatch):
    manager = ValidationManager(mode="symbolic")
    binary = _FakeBinary()

    class _FakeFactory:
        @staticmethod
        def successors(state, num_inst=1):
            assert num_inst == 1
            return SimpleNamespace(
                flat_successors=[SimpleNamespace(addr=state.addr + 1)],
                unsat_successors=[],
            )

    class _FakeProject:
        factory = _FakeFactory()

    class _FakeBridge:
        def __init__(self, _binary):
            self.angr_project = _FakeProject()

        @staticmethod
        def create_symbolic_state(address):
            return SimpleNamespace(addr=address)

    monkeypatch.setattr(
        "r2morph.validation.manager.import_module",
        lambda _name: SimpleNamespace(ANGR_AVAILABLE=True, AngrBridge=_FakeBridge),
    )

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

    assert outcome.metadata["symbolic_status"] == "bounded-step-passed"
    assert outcome.metadata["symbolic_step_count"] == 1
    assert outcome.metadata["symbolic_flat_successors"] == 1
    assert outcome.metadata["symbolic_unsat_successors"] == 0
    assert outcome.metadata["symbolic_stepped_regions"] == [
        {
            "start_address": 0x401010,
            "end_address": 0x401011,
            "flat_successors": 1,
            "unsat_successors": 0,
            "successor_addresses": [0x401011],
            "step_budget": 1,
        }
    ]


def test_symbolic_pipeline_marks_known_instruction_equivalence_as_supported(monkeypatch):
    class _FakeFactory:
        @staticmethod
        def successors(state, num_inst=1):
            return SimpleNamespace(
                flat_successors=[SimpleNamespace(addr=state.addr + 1)],
                unsat_successors=[],
            )

    class _FakeProject:
        factory = _FakeFactory()

    class _FakeBridge:
        def __init__(self, _binary):
            self.angr_project = _FakeProject()

        @staticmethod
        def create_symbolic_state(address):
            return SimpleNamespace(addr=address)

    monkeypatch.setattr(
        "r2morph.validation.manager.import_module",
        lambda _name: SimpleNamespace(ANGR_AVAILABLE=True, AngrBridge=_FakeBridge),
    )

    pipeline = Pipeline()
    pipeline.add_pass(_InstructionSubstitutionSemanticPass())

    result = pipeline.run(
        _FakeBinary(),
        session=_FakeSession(),
        validation_manager=ValidationManager(mode="symbolic"),
    )

    symbolic = result["validation"]["symbolic"]
    assert symbolic["requested"] is True
    assert symbolic["supported_passes"] == ["InstructionSubstitution"]
    assert symbolic["fallback_passes"] == []
    assert symbolic["statuses"][0]["status"] == "bounded-step-known-equivalence"


def test_symbolic_pipeline_marks_observable_match_as_supported(monkeypatch):
    class _FakeFactory:
        @staticmethod
        def successors(state, num_inst=1):
            return SimpleNamespace(
                flat_successors=[SimpleNamespace(addr=state.addr + 1)],
                unsat_successors=[],
            )

    class _FakeProject:
        factory = _FakeFactory()

    class _FakeBridge:
        def __init__(self, _binary):
            self.angr_project = _FakeProject()

        @staticmethod
        def create_symbolic_state(address):
            return SimpleNamespace(addr=address)

    monkeypatch.setattr(
        "r2morph.validation.manager.import_module",
        lambda _name: SimpleNamespace(ANGR_AVAILABLE=True, AngrBridge=_FakeBridge, angr=None),
    )
    monkeypatch.setattr(
        ValidationManager,
        "_compare_instruction_substitution_observables",
        lambda self, binary, pass_result, bridge_module: {
            "symbolic_observable_check_performed": True,
            "symbolic_observable_equivalent": True,
            "symbolic_observable_reason": "observable register/flag effects matched",
            "symbolic_observable_regions": [
                {
                    "start_address": 0x401010,
                    "end_address": 0x401011,
                    "observables_checked": ["eax", "eflags"],
                    "original_successors": 1,
                    "mutated_successors": 1,
                    "mismatches": [],
                }
            ],
            "symbolic_observable_mismatches": [],
        },
    )

    pipeline = Pipeline()
    pipeline.add_pass(_InstructionSubstitutionSemanticPass())

    result = pipeline.run(
        _FakeBinary(),
        session=_FakeSession(),
        validation_manager=ValidationManager(mode="symbolic"),
    )

    symbolic = result["validation"]["symbolic"]
    assert symbolic["requested"] is True
    assert symbolic["supported_passes"] == ["InstructionSubstitution"]
    assert symbolic["fallback_passes"] == []
    assert symbolic["statuses"][0]["status"] == "bounded-step-observables-match"
    mutation = result["mutations"][0]
    assert mutation["metadata"]["symbolic_requested"] is True
    assert mutation["metadata"]["symbolic_status"] == "bounded-step-observables-match"
    assert mutation["metadata"]["symbolic_observable_check_performed"] is True
    assert mutation["metadata"]["symbolic_observable_equivalent"] is True
    assert mutation["metadata"]["symbolic_observables_checked"] == ["eax", "eflags"]


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

    assert report["input"]["path"] == "in.bin"
    assert report["output"]["working_path"] == "work.bin"
    assert report["summary"]["total_mutations"] == 1
    assert report["summary"]["rolled_back_passes"] == 1
    assert report["summary"]["discarded_mutations"] == 1
    assert report["summary"]["symbolic_issue_passes"] == []
    assert report["summary"]["symbolic_coverage_by_pass"] == []
    assert report["summary"]["symbolic_severity_by_pass"][0]["pass_name"] == "RecordingPass"
    assert report["summary"]["symbolic_severity_by_pass"][0]["severity"] == "not-requested"
    assert report["summary"]["symbolic_issue_map"] == {}
    assert report["summary"]["symbolic_coverage_map"] == {}
    assert report["summary"]["symbolic_severity_map"]["RecordingPass"]["pass_name"] == "RecordingPass"
    assert report["summary"]["symbolic_status_counts"] == {}
    assert report["summary"]["symbolic_status_rows"] == []
    assert report["summary"]["symbolic_status_map"] == {}
    assert report["summary"]["symbolic_overview"]["symbolic_requested"] == 0
    assert report["summary"]["observable_mismatch_by_pass"] == []
    assert report["summary"]["observable_mismatch_map"] == {}
    assert report["summary"]["observable_mismatch_priority"] == []
    assert report["summary"]["pass_evidence"][0]["pass_name"] == "RecordingPass"
    assert report["summary"]["pass_evidence_priority"][0]["pass_name"] == "RecordingPass"
    assert report["summary"]["pass_coverage_buckets"]["uncovered"] == ["RecordingPass"]
    assert report["summary"]["pass_risk_buckets"]["clean"] == ["RecordingPass"]
    assert report["summary"]["pass_symbolic_summary"]["RecordingPass"]["severity"] == "not-requested"
    assert report["summary"]["pass_capabilities"]["RecordingPass"] == {}
    assert report["summary"]["pass_capability_summary"][0]["pass_name"] == "RecordingPass"
    assert report["summary"]["pass_capability_summary_map"]["RecordingPass"]["pass_name"] == "RecordingPass"
    assert report["summary"]["validation_role_rows"] == []
    assert report["summary"]["validation_role_map"] == {}
    assert report["summary"]["validation_adjustments"]["degraded_validation"] is False
    assert report["summary"]["pass_evidence_map"]["RecordingPass"]["pass_name"] == "RecordingPass"
    assert report["summary"]["pass_triage_rows"][0]["pass_name"] == "RecordingPass"
    assert report["summary"]["pass_triage_map"]["RecordingPass"]["pass_name"] == "RecordingPass"
    assert report["summary"]["pass_evidence_compact"][0]["pass_name"] == "RecordingPass"
    assert report["summary"]["discarded_mutation_summary"]["by_pass"] == []
    assert report["summary"]["discarded_mutation_priority"] == []
    assert report["passes"]["RecordingPass"]["evidence_summary"]["pass_name"] == "RecordingPass"
    assert report["pass_evidence"][0]["pass_name"] == "RecordingPass"
    assert report["pass_evidence_priority"][0]["pass_name"] == "RecordingPass"
    assert report["pass_coverage_buckets"]["uncovered"] == ["RecordingPass"]
    assert report["pass_risk_buckets"]["clean"] == ["RecordingPass"]
    assert report["pass_symbolic_summary"]["RecordingPass"]["severity"] == "not-requested"
    assert report["symbolic_issue_map"] == {}
    assert report["symbolic_coverage_map"] == {}
    assert report["symbolic_severity_map"]["RecordingPass"]["pass_name"] == "RecordingPass"
    assert report["symbolic_status_counts"] == {}
    assert report["symbolic_status_rows"] == []
    assert report["symbolic_status_map"] == {}
    assert report["symbolic_overview"]["symbolic_requested"] == 0
    assert report["observable_mismatch_by_pass"] == []
    assert report["observable_mismatch_map"] == {}
    assert report["observable_mismatch_priority"] == []
    assert report["pass_capabilities"]["RecordingPass"] == {}
    assert report["pass_capability_summary"][0]["pass_name"] == "RecordingPass"
    assert report["pass_capability_summary_map"]["RecordingPass"]["pass_name"] == "RecordingPass"
    assert report["validation_role_rows"] == []
    assert report["validation_role_map"] == {}
    assert report["validation_adjustments"]["degraded_validation"] is False
    assert report["pass_evidence_map"]["RecordingPass"]["pass_name"] == "RecordingPass"
    assert report["pass_region_evidence_map"] == {}
    assert report["pass_triage_rows"][0]["pass_name"] == "RecordingPass"
    assert report["pass_triage_map"]["RecordingPass"]["pass_name"] == "RecordingPass"
    assert report["pass_evidence_compact"][0]["pass_name"] == "RecordingPass"
    assert report["normalized_pass_results"][0]["pass_name"] == "RecordingPass"
    assert report["report_views"]["passes"]["uncovered"] == ["RecordingPass"]
    assert report["report_views"]["general_passes"][0]["pass_name"] == "RecordingPass"
    assert report["report_views"]["general_passes"][0]["region_evidence_count"] == 0
    assert report["report_views"]["general_pass_rows"][0]["pass_name"] == "RecordingPass"
    assert report["report_views"]["general_pass_rows"][0]["gate_failure_count"] == 0
    assert report["report_views"]["general_pass_rows"][0]["discarded_count"] == 0
    assert report["report_views"]["general_filter_views"] == {
        "risky": [],
        "structural_risk": [],
        "symbolic_risk": [],
        "clean": ["RecordingPass"],
        "covered": [],
        "uncovered": ["RecordingPass"],
    }
    assert report["report_views"]["general_triage_rows"][0]["pass_name"] == "RecordingPass"
    assert report["report_views"]["general_summary"] == {
        "pass_count": 1,
        "passes": ["RecordingPass"],
        "risky_pass_count": 0,
        "clean_pass_count": 1,
        "covered_pass_count": 0,
        "uncovered_pass_count": 1,
    }
    assert report["report_views"]["general_summary_rows"][0]["section"] == "passes"
    assert report["report_views"]["general_renderer_state"]["summary"]["pass_count"] == 1
    assert report["report_views"]["general_renderer_state"]["general_summary"]["pass_count"] == 1
    assert report["report_views"]["general_renderer_state"]["summary_rows"][0]["section"] == "passes"
    assert report["report_views"]["general_renderer_state"]["general_summary_rows"][0]["section"] == "passes"
    assert report["report_views"]["general_renderer_state"]["symbolic"] == {
        "symbolic_requested": 0,
        "observable_match": 0,
        "observable_mismatch": 0,
        "bounded_only": 0,
        "without_coverage": 0,
    }
    assert report["report_views"]["general_renderer_state"]["general_symbolic"] == {
        "symbolic_requested": 0,
        "observable_match": 0,
        "observable_mismatch": 0,
        "bounded_only": 0,
        "without_coverage": 0,
    }
    assert report["report_views"]["general_renderer_state"]["general_gates"] == {
        "failed": False,
        "failure_count": 0,
        "pass_count": 0,
        "expected_severity_counts": {},
        "severity_priority": [],
        "passes": [],
    }
    assert report["report_views"]["general_renderer_state"]["general_degradation"] == {
        "requested_validation_mode": None,
        "effective_validation_mode": None,
        "degraded_validation": False,
        "row_count": 0,
        "passes": [],
        "gate_failure_count": 0,
    }
    assert report["report_views"]["general_renderer_state"]["general_discards"] == {
        "count": 0,
        "passes": [],
        "reasons": {},
        "impacts": {"high": 0, "medium": 0, "low": 0},
    }
    assert report["report_views"]["general_renderer_state"]["filter_views"] == {
        "risky": [],
        "structural_risk": [],
        "symbolic_risk": [],
        "clean": ["RecordingPass"],
        "covered": [],
        "uncovered": ["RecordingPass"],
    }
    assert report["report_views"]["general_renderer_state"]["general_filter_views"] == {
        "risky": [],
        "structural_risk": [],
        "symbolic_risk": [],
        "clean": ["RecordingPass"],
        "covered": [],
        "uncovered": ["RecordingPass"],
    }
    assert report["report_views"]["general_renderer_state"]["pass_rows"][0]["pass_name"] == "RecordingPass"
    assert report["report_views"]["general_renderer_state"]["general_passes"][0]["pass_name"] == "RecordingPass"
    assert report["report_views"]["general_renderer_state"]["general_pass_rows"][0]["pass_name"] == "RecordingPass"
    assert report["report_views"]["general_renderer_state"]["general_triage_rows"][0]["pass_name"] == "RecordingPass"
    assert report["report_views"]["general_symbolic"]["overview"] == {
        "symbolic_requested": 0,
        "observable_match": 0,
        "observable_mismatch": 0,
        "bounded_only": 0,
        "without_coverage": 0,
    }
    assert report["report_views"]["general_gates"]["summary"] == {}
    assert report["report_views"]["general_degradation"]["summary"] == {
        "requested_validation_mode": None,
        "effective_validation_mode": None,
        "degraded_validation": False,
        "row_count": 0,
        "passes": [],
        "gate_failure_count": 0,
    }
    assert report["report_views"]["general_discards"]["summary"] == {
        "count": 0,
        "passes": [],
        "reasons": {},
        "impacts": {"high": 0, "medium": 0, "low": 0},
    }
    assert report["report_views"]["triage_priority"][0]["pass_name"] == "RecordingPass"
    assert report["report_views"]["only_pass"]["RecordingPass"]["normalized"]["pass_name"] == "RecordingPass"
    assert report["report_views"]["only_pass"]["RecordingPass"]["region_evidence"] == []
    assert report["report_views"]["pass_filter_views"]["only_clean_passes"] == ["RecordingPass"]
    assert report["report_views"]["mismatch_view"] == []
    assert report["report_views"]["only_mismatches"]["priority"] == []
    assert report["report_views"]["only_mismatches"]["rows"] == []
    assert report["report_views"]["only_mismatches"]["compact_rows"] == []
    assert report["report_views"]["only_mismatches"]["final_rows"] == []
    assert report["report_views"]["only_mismatches"]["final_by_pass"] == {}
    assert report["report_views"]["only_mismatches"]["compact_by_pass"] == {}
    assert report["report_views"]["only_mismatches"]["compact_summary"] == {
        "pass_count": 0,
        "mismatch_count": 0,
        "degraded_pass_count": 0,
        "region_count": 0,
        "region_mismatch_count": 0,
        "region_exit_match_count": 0,
        "passes": [],
    }
    assert report["report_views"]["only_mismatches"]["summary"] == {
        "pass_count": 0,
        "mismatch_count": 0,
        "degraded_pass_count": 0,
        "trigger_pass_count": 0,
        "region_count": 0,
        "region_mismatch_count": 0,
        "region_exit_match_count": 0,
        "passes": [],
    }
    assert report["report_views"]["only_failed_gates"]["priority"] == []
    assert report["report_views"]["only_failed_gates"]["severity_priority"] == []
    assert report["report_views"]["only_failed_gates"]["grouped_by_pass"] == []
    assert report["report_views"]["only_failed_gates"]["compact_rows"] == []
    assert report["report_views"]["only_failed_gates"]["final_rows"] == []
    assert report["report_views"]["only_failed_gates"]["final_by_pass"] == {}
    assert report["report_views"]["only_failed_gates"]["compact_by_pass"] == {}
    assert report["report_views"]["only_failed_gates"]["expected_severity_counts"] == {}
    assert report["report_views"]["only_failed_gates"]["failed"] is False
    assert report["report_views"]["only_failed_gates"]["failure_count"] == 0
    assert report["report_views"]["only_failed_gates"]["pass_count"] == 0
    assert report["report_views"]["only_failed_gates"]["passes"] == []
    assert report["report_views"]["only_failed_gates"]["compact_summary"] == {
        "failed": False,
        "failure_count": 0,
        "pass_count": 0,
        "expected_severity_counts": {},
        "severity_priority": [],
        "passes": [],
    }
    assert report["report_views"]["validation_adjustments"]["rows"] == []
    assert report["report_views"]["validation_adjustments"]["compact_rows"] == []
    assert report["report_views"]["validation_adjustments"]["compact_by_pass"] == {}
    assert report["report_views"]["validation_adjustments"]["summary"] == {
        "requested_validation_mode": None,
        "effective_validation_mode": None,
        "row_count": 0,
        "trigger_count": 0,
        "degraded_execution_count": 0,
        "degraded_validation": False,
        "gate_failure_count": 0,
        "passes": [],
    }
    assert report["report_views"]["validation_adjustments"]["compact_summary"] == {
        "degraded_validation": False,
        "row_count": 0,
        "trigger_count": 0,
        "degraded_execution_count": 0,
        "gate_failure_count": 0,
        "passes": [],
    }
    assert report["report_views"]["discarded_view"]["by_reason"] == {}
    assert report["report_views"]["discarded_view"]["compact_by_reason"] == {}
    assert report["report_views"]["discarded_view"]["rows"] == []
    assert report["report_views"]["discarded_view"]["compact_rows"] == []
    assert report["report_views"]["discarded_view"]["final_rows"] == []
    assert report["report_views"]["discarded_view"]["final_by_pass"] == {}
    assert report["report_views"]["discarded_view"]["compact_by_pass"] == {}
    assert report["report_views"]["discarded_view"]["by_impact"] == {
        "high": [],
        "medium": [],
        "low": [],
    }
    assert report["report_views"]["discarded_view"]["summary"] == {
        "count": 0,
        "passes": [],
        "reasons": [],
        "impacts": {"high": 0, "medium": 0, "low": 0},
    }
    assert report["report_views"]["discarded_view"]["compact_summary"] == {
        "count": 0,
        "pass_count": 0,
        "reason_count": 0,
        "impact_counts": {"high": 0, "medium": 0, "low": 0},
        "passes": [],
    }
    assert report["schema_version"] == 1
    assert report["summary"]["schema_version"] == 1
    assert report["validation_adjustment_rows"] == []
    assert report["discarded_mutation_summary"]["by_pass"] == []
    assert report["discarded_mutation_priority"] == []
    assert report["passes"]["RecordingPass"]["symbolic_summary"]["symbolic_requested"] == 0
    assert report["passes"]["RecordingPass"]["symbolic_summary"]["severity"] == "not-requested"


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

    assert region_map["ExamplePass"][0]["region_exit_equivalent"] is True
    assert region_map["ExamplePass"][1]["region_exit_equivalent"] is False


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

    assert report["pass_symbolic_summary"]["RecordingPass"]["pass_name"] == "RecordingPass"
    assert report["summary"]["pass_symbolic_summary"]["RecordingPass"]["pass_name"] == ("RecordingPass")
    assert report["pass_validation_context"]["RecordingPass"]["role"] == "degradation-trigger"
    assert report["summary"]["pass_validation_context"]["RecordingPass"]["role"] == ("degradation-trigger")


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

    assert coverage["covered"] == ["InstructionSubstitution"]
    assert coverage["uncovered"] == ["ReportFixture"]
    assert sorted(coverage["clean_only"]) == ["InstructionSubstitution", "ReportFixture"]
    assert risk["risky"] == ["RegisterSubstitution"]
    assert risk["symbolic"] == ["RegisterSubstitution"]
    assert sorted(risk["clean"]) == ["InstructionSubstitution", "ReportFixture"]
    assert risk["covered"] == ["InstructionSubstitution"]
    assert risk["uncovered"] == ["ReportFixture"]
