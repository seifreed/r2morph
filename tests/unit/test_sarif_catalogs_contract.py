from __future__ import annotations

from r2morph.reporting.sarif_catalogs import MITRE_ATTACK, MUTATION_RULES, VALIDATION_RULES
from tests.utils.assertions import expect

_EXPECTED_LEN_MUTATION_RULES_8 = 8
_EXPECTED_LEN_VALIDATION_RULES_4 = 4


def test_sarif_catalogs_have_expected_shape() -> None:
    expect(not (len(MUTATION_RULES) < _EXPECTED_LEN_MUTATION_RULES_8))
    expect(not (len(VALIDATION_RULES) < _EXPECTED_LEN_VALIDATION_RULES_4))
    expect(not ("nop" not in MITRE_ATTACK))
    expect(not ("control-flow-flattening" not in MITRE_ATTACK))
    expect(all("id" in entry and "name" in entry for entry in MITRE_ATTACK.values()))
