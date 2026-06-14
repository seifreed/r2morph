from r2morph.cli_workflow_selection import build_config, limited_symbolic_passes, mutation_pass_alias_map


def test_cli_workflow_selection_builds_aliases_and_limited_lists() -> None:
    config = build_config(False, False)
    alias_map = mutation_pass_alias_map(config, seed=0)

    assert "nop" in alias_map
    assert alias_map["nop"] == alias_map[alias_map["nop"]]
    assert limited_symbolic_passes(["nop"], config, seed=0) == []
