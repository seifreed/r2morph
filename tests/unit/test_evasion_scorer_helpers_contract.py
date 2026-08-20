from r2morph.detection.evasion_scorer_helpers import compose_evasion_score, recommend_improvements
from tests.utils.assertions import expect


def test_evasion_scorer_helpers_contract() -> None:
    score = compose_evasion_score(
        hash_score=100.0,
        entropy_score=80.0,
        structure_score=40.0,
        signature_score=20.0,
    )
    expect(not (score.details["hash_changed"] is not True))
    expect(not (score.details["entropy_similar"] is not True))
    expect(not (score.details["structure_changed"] is not False))

    recs = recommend_improvements(score)
    expect(recs)
