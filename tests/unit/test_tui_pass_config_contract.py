from r2morph.tui_pass_config import TUIPassConfig


def test_tui_pass_config_round_trip() -> None:
    config = TUIPassConfig("demo", {"enabled": True, "count": 3})

    assert config.get_option("enabled") is True
    assert config.get_option("missing", "fallback") == "fallback"

    config.set_option("count", 4)
    assert config.config["count"] == 4
