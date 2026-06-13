"""Contract tests for cache-backed call graph construction."""

from pathlib import Path

from r2morph.analysis.call_graph import CallGraph
from r2morph.analysis.call_graph_cache import build_call_graph_cached


class _StubCache:
    def __init__(self) -> None:
        self.store: dict[tuple[bytes, str, tuple[tuple[str, bool], ...]], str] = {}

    def _key(self, data: bytes, analysis_type: str, options: dict[str, bool]) -> tuple[bytes, str, tuple[tuple[str, bool], ...]]:
        return (data, analysis_type, tuple(sorted(options.items())))

    def get(self, data: bytes, analysis_type: str, options: dict[str, bool]) -> str | None:
        return self.store.get(self._key(data, analysis_type, options))

    def set(self, data: bytes, analysis_type: str, value: str, options: dict[str, bool]) -> None:
        self.store[self._key(data, analysis_type, options)] = value


class _StubBinary:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._functions = [{"offset": 0x1000, "name": "main", "size": 4}]
        self._disasm = {0x1000: [{"disasm": "ret", "offset": 0x1000}]}
        self.analyzed = True

    def is_analyzed(self) -> bool:
        return self.analyzed

    def get_functions(self) -> list[dict[str, int | str]]:
        return self._functions

    def get_function_disasm(self, func_addr: int) -> list[dict[str, int | str]]:
        return self._disasm.get(func_addr, [])


def test_build_call_graph_cached_without_cache(tmp_path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"abc")
    binary = _StubBinary(binary_path)

    cg = build_call_graph_cached(binary, cache=None)

    assert isinstance(cg, CallGraph)


def test_build_call_graph_cached_round_trip(tmp_path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"abc")
    binary = _StubBinary(binary_path)
    cache = _StubCache()

    cg1 = build_call_graph_cached(binary, cache=cache)
    cg2 = build_call_graph_cached(binary, cache=cache)

    assert isinstance(cg1, CallGraph)
    assert isinstance(cg2, CallGraph)
    assert cg1.to_json() == cg2.to_json()
