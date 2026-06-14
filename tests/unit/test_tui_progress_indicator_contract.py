from r2morph.tui_progress_indicator import TUIProgressIndicator


def test_tui_progress_indicator_lifecycle() -> None:
    indicator = TUIProgressIndicator()

    indicator.start(3, description="Working")
    indicator.update()
    indicator.complete("Done")
    indicator.stop()

    assert indicator.console is not None
