from types import SimpleNamespace

from r2morph.validation.binary_region_memory import collect_memory_write_signatures


def test_collect_memory_write_signatures_handles_missing_history() -> None:
    assert collect_memory_write_signatures(SimpleNamespace(history=None)) == []


def test_collect_memory_write_signatures_dedupes_and_formats_signatures() -> None:
    actions = [
        SimpleNamespace(type="mem", action="write", addr=SimpleNamespace(concrete_value=0x1000), size=4),
        SimpleNamespace(type="mem", action="store", addr=SimpleNamespace(concrete_value=0x1000), size=4),
        SimpleNamespace(type="mem", action="write", addr=SimpleNamespace(concrete_value=0x2000), size=None),
    ]
    state = SimpleNamespace(history=SimpleNamespace(actions=actions))
    assert collect_memory_write_signatures(state) == ["0x1000:4", "0x2000"]
