"""Contract tests for binary lifecycle helpers."""

from __future__ import annotations

from pathlib import Path

from r2morph.core.binary import Binary


class _FakeDisassembler:
    def __init__(self) -> None:
        self.open_calls: list[tuple[Path, list[str]]] = []
        self.cmd_calls: list[str] = []
        self.quit_calls = 0
        self.opened = False

    def open(self, path: Path, flags: list[str] | None = None) -> None:
        self.opened = True
        self.open_calls.append((path, list(flags or [])))

    def cmdj(self, command: str):
        if command == "ij":
            return {"core": {"format": "elf"}, "bin": {"arch": "x86_64", "bits": 64}}
        if command == "aflj":
            return [{"name": "main"}] if self.cmd_calls else []
        return []

    def cmd(self, command: str) -> None:
        self.cmd_calls.append(command)

    def quit(self) -> None:
        self.quit_calls += 1
        self.opened = False


def test_binary_lifecycle_open_and_close_with_injected_disassembler(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x00" * 64)
    disassembler = _FakeDisassembler()

    binary = Binary(binary_path, writable=True, disassembler=disassembler)
    binary.open()

    assert binary.r2 is disassembler
    assert disassembler.open_calls[0][0] == binary.path
    assert "-w" in disassembler.open_calls[0][1]

    binary.close()

    assert disassembler.quit_calls == 1
    assert binary.r2 is None


def test_binary_lifecycle_reload_reopens_and_reanalyzes(tmp_path: Path) -> None:
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x00" * 64)
    disassembler = _FakeDisassembler()

    binary = Binary(binary_path, disassembler=disassembler)
    binary.open()
    binary.analyze("aaa")
    assert binary.is_analyzed() is True

    binary.reload()

    assert len(disassembler.open_calls) == 2
    assert disassembler.cmd_calls == ["aaa", "aaa"]
    assert binary.is_analyzed() is True
    assert binary.get_functions() == [{"name": "main"}]
    binary.close()
