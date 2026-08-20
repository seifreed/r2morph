from r2morph.reporting.sarif_rule_ids import get_mutation_rule_id, get_validation_rule_id
from tests.utils.assertions import expect


def test_sarif_rule_ids_contract() -> None:
    expect(get_mutation_rule_id("nop-insertion") == "RM001")
    expect(get_mutation_rule_id("control-flow-flattening") == "RM008")
    expect(get_mutation_rule_id("unknown") == "RM001")

    expect(get_validation_rule_id("cfg-integrity") == "RV004")
    expect(get_validation_rule_id("runtime") == "RV002")
    expect(get_validation_rule_id("unknown") == "RV001")
