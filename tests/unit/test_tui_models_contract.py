from r2morph.tui_models import TUIAction, TUIFunction, TUIMutation, TUIPass, TUIProgress, TUIResult


def test_tui_models_are_plain_data() -> None:
    funcs = [TUIFunction(address=0x1000, name="main", size=16)]
    passes = [TUIPass(name="nop", description="Insert NOP", is_stable=True)]
    result = TUIResult(functions=funcs, passes=passes, confirmed=True)
    mutation = TUIMutation(
        address=0x1000,
        function="main",
        pass_name="nop",
        original_bytes=b"\x90",
        mutated_bytes=b"\x90\x90",
    )
    progress = TUIProgress(total=2, current=1, message="running")

    assert result.confirmed is True
    assert mutation.pass_name == "nop"
    assert progress.status == "running"
    assert TUIAction.CONFIRM.value == "confirm"
