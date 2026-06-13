"""Contract tests for engine lifecycle helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from r2morph.core.engine_lifecycle import (
    analyze,
    auto_detect_analysis_level,
    create_working_copy,
    get_binary_size_mb,
    should_enable_memory_efficient_mode,
    should_use_low_memory,
)


class _FakeBinary:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.analyzed: list[str] = []

    def analyze(self, level: str) -> None:
        self.analyzed.append(level)

    def get_functions(self) -> list[int]:
        return [1, 2]

    def get_arch_info(self) -> dict[str, object]:
        return {"arch": "x86", "bits": 64, "format": "elf"}


def test_engine_lifecycle_file_helpers_work(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x00" * 1024)

    assert create_working_copy(binary_path).name == "sample.bin.working"
    assert get_binary_size_mb(binary_path) > 0
    assert should_use_low_memory(binary_path) is False
    assert should_enable_memory_efficient_mode(0.1, 1) is False


def test_engine_lifecycle_analyze_updates_engine_state(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x00" * 1024)
    fake_engine = SimpleNamespace(
        binary=_FakeBinary(binary_path),
        _stats={},
        _memory_efficient_mode=False,
    )

    analyze(fake_engine, "aaa")

    assert fake_engine._stats["functions"] == 2
    assert fake_engine._stats["arch"] == "x86"
    assert fake_engine._stats["bits"] == 64
    assert fake_engine._stats["format"] == "elf"
    assert fake_engine.binary.analyzed == ["aaa"]
    assert auto_detect_analysis_level(fake_engine) in {"aa", "aac", "aaa"}
