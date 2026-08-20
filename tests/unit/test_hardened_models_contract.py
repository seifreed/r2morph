from r2morph.mutations.hardened_models import HardenedMutationResult
from tests.utils.assertions import expect

_EXPECTED_PAYLOAD_INTEGRITY_VIOLATIONS_4 = 4
_EXPECTED_PAYLOAD_PATTERNS_PRESERVED_3 = 3


def test_hardened_mutation_result_includes_extended_fields():
    result = HardenedMutationResult(
        success=True,
        mutations_applied=2,
        patterns_preserved=3,
        patterns_avoided=1,
        integrity_violations=4,
        preservation_report={"preserved": 3},
        integrity_report={"violations": 4},
    )

    payload = result.to_dict()

    expect(payload["patterns_preserved"] == _EXPECTED_PAYLOAD_PATTERNS_PRESERVED_3)
    expect(payload["patterns_avoided"] == 1)
    expect(payload["integrity_violations"] == _EXPECTED_PAYLOAD_INTEGRITY_VIOLATIONS_4)
    expect(payload["preservation_report"] == {"preserved": 3})
    expect(payload["integrity_report"] == {"violations": 4})
