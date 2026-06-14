from r2morph.tui import TUIFunction
from r2morph.tui_filters import FunctionFilter


def test_tui_filters_contract() -> None:
    funcs = [
        TUIFunction(address=0x1000, name="main", size=16),
        TUIFunction(address=0x2000, name="helper", size=8),
    ]

    filt = FunctionFilter()
    filt.set_pattern("main")
    filt.set_size_range(8, 16)

    assert filt.matches(funcs[0]) is True
    assert filt.matches(funcs[1]) is False
    assert filt.filter_functions(funcs) == [funcs[0]]
