from r2morph.validation.mutation_annotator_instruction import annotate_instruction_substitution_evidence
from tests.utils.assertions import expect


def test_instruction_substitution_evidence_populates_expected_fields() -> None:
    mutation_metadata: dict[str, object] = {}
    annotate_instruction_substitution_evidence(
        mutation_metadata,
        (0x401010, 0x401011),
        {
            "symbolic_semantic_hint": "known-equivalence-group",
            "symbolic_semantic_hint_supported": True,
        },
        {
            (0x401010, 0x401011): {
                "mismatches": [],
                "observables_checked": ["eax", "eflags"],
            }
        },
        {
            (0x401010, 0x401011): {
                "mismatches": [],
            }
        },
    )

    expect(mutation_metadata["symbolic_semantic_hint"] == "known-equivalence-group")
    expect(not (mutation_metadata["symbolic_semantic_hint_supported"] is not True))
    expect(not (mutation_metadata["symbolic_observable_check_performed"] is not True))
    expect(not (mutation_metadata["symbolic_transition_check_performed"] is not True))
