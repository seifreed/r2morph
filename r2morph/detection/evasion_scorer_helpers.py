"""Pure scoring helpers for evasion analysis."""

from __future__ import annotations

from r2morph.detection.evasion_scorer_models import EvasionScore

DEFAULT_EVASION_WEIGHTS = {
    "hash_change": 0.25,
    "entropy": 0.20,
    "structure": 0.30,
    "signature": 0.25,
}


def compose_evasion_score(
    *,
    hash_score: float,
    entropy_score: float,
    structure_score: float,
    signature_score: float,
    weights: dict[str, float] | None = None,
) -> EvasionScore:
    """Compose the final evasion score from component scores."""
    weights = weights or DEFAULT_EVASION_WEIGHTS
    overall = (
        hash_score * weights["hash_change"]
        + entropy_score * weights["entropy"]
        + structure_score * weights["structure"]
        + signature_score * weights["signature"]
    )

    return EvasionScore(
        overall_score=overall,
        hash_change_score=hash_score,
        entropy_score=entropy_score,
        structure_score=structure_score,
        signature_score=signature_score,
        details={
            "hash_changed": hash_score == 100.0,
            "entropy_similar": entropy_score > 70.0,
            "structure_changed": structure_score > 50.0,
        },
    )


def recommend_improvements(score: EvasionScore) -> list[str]:
    """Generate human-readable evasion improvement hints."""
    recommendations = []

    if score.hash_change_score < 100:
        recommendations.append("⚠️ Hash didn't change - ensure mutations are applied")

    if score.entropy_score < 50:
        recommendations.append("⚠️ Entropy changed significantly - may look suspicious")

    if score.structure_score < 30:
        recommendations.append("💡 Consider more aggressive mutations to change structure")

    if score.signature_score < 40:
        recommendations.append("💡 Byte patterns too similar - add more instruction substitutions")

    if score.overall_score > 80:
        recommendations.append("✅ Excellent evasion score!")
    elif score.overall_score > 60:
        recommendations.append("👍 Good evasion score")
    elif score.overall_score > 40:
        recommendations.append("⚠️ Moderate evasion - consider more mutations")
    else:
        recommendations.append("🔴 Low evasion score - mutations may be ineffective")

    return recommendations
