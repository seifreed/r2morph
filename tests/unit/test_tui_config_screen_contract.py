from r2morph.tui_config_screen import TUIConfigScreen


def test_tui_config_screen_can_create_and_update_configs() -> None:
    screen = TUIConfigScreen()

    config = screen.get_config("demo")
    assert config.pass_name == "demo"

    updated = screen.handle_input("use_equiv=true", "nop", {"use_equiv": False})
    assert updated["use_equiv"] is True

    defaults = screen.handle_input("d", "demo", {"enabled": False})
    assert isinstance(defaults, dict)
