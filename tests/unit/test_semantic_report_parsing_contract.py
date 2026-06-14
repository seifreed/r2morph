from r2morph.validation.semantic_invariant_models import InvariantCategory, InvariantSeverity
from r2morph.validation.semantic_models import ValidationMode, ValidationResultStatus
from r2morph.validation.semantic_report_parsing import (
    build_observable_comparison,
    build_semantic_validation_report,
    build_semantic_validation_result,
)


def test_build_semantic_validation_result_parses_nested_payload() -> None:
    payload = {
        "region": {
            "start_address": 0x1000,
            "end_address": 0x1004,
            "original_bytes": "0102",
            "mutated_bytes": "0304",
            "pass_name": "nop",
            "function_address": 0x2000,
            "original_disasm": "mov eax, ebx",
            "mutated_disasm": "nop",
            "metadata": {"source": "unit"},
        },
        "status": "pass",
        "checks": [
            {
                "check_name": "stack",
                "category": "stack",
                "passed": True,
                "message": "ok",
                "details": {"width": 4},
            }
        ],
        "violations": [
            {
                "invariant_name": "stack-clean",
                "category": "stack",
                "severity": "warning",
                "address_range": [0x1000, 0x1004],
                "message": "note",
                "expected": "expected",
                "actual": "actual",
                "repair_hint": "hint",
                "metadata": {"kind": "demo"},
            }
        ],
        "observables": None,
        "symbolic_status": "checked",
        "symbolic_details": {"mode": "real"},
        "execution_time_seconds": 1.25,
        "error_message": None,
    }

    parsed = build_semantic_validation_result(payload)

    assert parsed["region"].pass_name == "nop"
    assert parsed["status"] == ValidationResultStatus.PASS
    assert parsed["checks"][0].category == InvariantCategory.STACK
    assert parsed["violations"][0].severity == InvariantSeverity.WARNING
    assert parsed["symbolic_status"] == "checked"
    assert parsed["symbolic_details"] == {"mode": "real"}
    assert parsed["execution_time_seconds"] == 1.25


def test_build_semantic_validation_report_parses_results_and_modes() -> None:
    data = {
        "binary_path": "sample.bin",
        "timestamp": "2026-06-14T00:00:00Z",
        "mode": "standard",
        "results": [],
        "summary": {"total_mutations": 0},
        "metadata": {"source": "unit"},
    }

    observables = build_observable_comparison(
        {
            "register_matches": {"rax": True},
            "register_values": {"rax": {"original": "1", "mutated": "2"}},
            "flag_matches": {"zf": False},
            "memory_matches": {"0x1000": True},
            "stack_delta_match": False,
            "successor_match": True,
            "successor_addresses": {"original": ["0x1000"], "mutated": ["0x2000"]},
        }
    )

    assert observables.to_dict() == {
        "register_matches": {"rax": True},
        "register_values": {"rax": {"original": "1", "mutated": "2"}},
        "flag_matches": {"zf": False},
        "memory_matches": {"0x1000": True},
        "stack_delta_match": False,
        "successor_match": True,
        "successor_addresses": {"original": ["0x1000"], "mutated": ["0x2000"]},
    }

    parsed = build_semantic_validation_report(data)

    assert parsed == {
        "binary_path": "sample.bin",
        "timestamp": "2026-06-14T00:00:00Z",
        "mode": ValidationMode.STANDARD,
        "results": [],
        "summary": {"total_mutations": 0},
        "metadata": {"source": "unit"},
    }
