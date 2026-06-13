from r2morph.mutations.hardened_models import HardenedMutationResult


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

    assert payload["patterns_preserved"] == 3
    assert payload["patterns_avoided"] == 1
    assert payload["integrity_violations"] == 4
    assert payload["preservation_report"] == {"preserved": 3}
    assert payload["integrity_report"] == {"violations": 4}
