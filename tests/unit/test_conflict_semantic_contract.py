from r2morph.mutations.conflict_semantic import SemanticConflictDetector
from tests.utils.assertions import expect

_EXPECTED_RESULT_TOTAL_CONFLICTS_2 = 2


def test_semantic_detector_reports_register_and_stack_conflicts() -> None:
    detector = SemanticConflictDetector(arch="x86")
    result = detector.detect_semantic_conflicts(
        [
            {"affected_registers": ["ebx"], "start": 0x1000, "size": 4},
            {"affected_registers": ["ebx"], "start": 0x2000, "size": 4},
            {"affected_registers": ["esp"], "control_flow_changed": False, "start": 0x3000, "size": 4},
            {"affected_registers": ["esp"], "control_flow_changed": False, "start": 0x4000, "size": 4},
        ]
    )

    expect(not (result["total_conflicts"] < _EXPECTED_RESULT_TOTAL_CONFLICTS_2))
    expect(not (result["has_critical"] is not True))
