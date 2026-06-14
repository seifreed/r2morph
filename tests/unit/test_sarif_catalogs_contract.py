from __future__ import annotations

from r2morph.reporting.sarif_catalogs import MITRE_ATTACK, MUTATION_RULES, VALIDATION_RULES


def test_sarif_catalogs_have_expected_shape() -> None:
    assert len(MUTATION_RULES) >= 8
    assert len(VALIDATION_RULES) >= 4
    assert "nop" in MITRE_ATTACK
    assert "control-flow-flattening" in MITRE_ATTACK
    assert all("id" in entry and "name" in entry for entry in MITRE_ATTACK.values())
