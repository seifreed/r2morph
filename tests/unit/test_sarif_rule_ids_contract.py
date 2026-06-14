from r2morph.reporting.sarif_rule_ids import get_mutation_rule_id, get_validation_rule_id


def test_sarif_rule_ids_contract() -> None:
    assert get_mutation_rule_id("nop-insertion") == "RM001"
    assert get_mutation_rule_id("control-flow-flattening") == "RM008"
    assert get_mutation_rule_id("unknown") == "RM001"

    assert get_validation_rule_id("cfg-integrity") == "RV004"
    assert get_validation_rule_id("runtime") == "RV002"
    assert get_validation_rule_id("unknown") == "RV001"
