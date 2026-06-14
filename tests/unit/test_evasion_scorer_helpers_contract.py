from r2morph.detection.evasion_scorer_helpers import compose_evasion_score, recommend_improvements


def test_evasion_scorer_helpers_contract() -> None:
    score = compose_evasion_score(
        hash_score=100.0,
        entropy_score=80.0,
        structure_score=40.0,
        signature_score=20.0,
    )
    assert score.details["hash_changed"] is True
    assert score.details["entropy_similar"] is True
    assert score.details["structure_changed"] is False

    recs = recommend_improvements(score)
    assert recs
