from r2morph.tui_presets import CONFIG_OPTIONS, CONFIG_TYPES, DEFAULT_PASS_CONFIGS, PASS_DESCRIPTIONS


def test_tui_presets_contract() -> None:
    assert DEFAULT_PASS_CONFIGS["nop"]["max_nops"] == 3
    assert PASS_DESCRIPTIONS["cff"][1] is False
    assert CONFIG_TYPES["opaque"]["predicate_type"] is str
    assert "jump_table" in CONFIG_OPTIONS["cff"]["dispatcher_style"]
