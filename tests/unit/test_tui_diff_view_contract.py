from r2morph.tui_diff_view import DiffView
from r2morph.tui_models import TUIMutation


def test_diff_view_navigation_and_current_item() -> None:
    view = DiffView()
    mutations = [
        TUIMutation(address=1, function="a", pass_name="p", original_bytes=b"\x01", mutated_bytes=b"\x02"),
        TUIMutation(address=2, function="b", pass_name="q", original_bytes=b"\x03", mutated_bytes=b"\x04"),
    ]

    view.set_mutations(mutations)

    assert view.current() == mutations[0]
    assert view.next() is True
    assert view.current() == mutations[1]
    assert view.next() is False
    assert view.previous() is True
    assert view.current() == mutations[0]
