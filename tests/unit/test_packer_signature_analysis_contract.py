"""Contract tests for packer signature analysis helpers."""

from __future__ import annotations

from r2morph.detection.packer_signature_analysis import (
    calculate_signature_confidence,
    detect_packing_layers,
    get_entry_bytes,
)
from r2morph.detection.packer_signature_models import PackerSignature, PackerType


class _FakeR2:
    def __init__(self, *, entry_hex: str = "", strings_output: str = "") -> None:
        self._entry_hex = entry_hex
        self._strings_output = strings_output

    def cmd(self, command: str) -> str:
        if command.startswith("p8") and "@" in command:
            return self._entry_hex
        if command == "izz":
            return self._strings_output
        return ""


class _FakeEntropyResult:
    def __init__(self, overall_entropy: float) -> None:
        self.overall_entropy = overall_entropy


class _FakeEntropyAnalyzer:
    def __init__(self, overall_entropy: float) -> None:
        self._overall_entropy = overall_entropy

    def analyze_file(self, _path):  # noqa: ANN001
        return _FakeEntropyResult(self._overall_entropy)


class _FakeBinary:
    def __init__(
        self,
        *,
        path: str = "sample.bin",
        r2: object | None = None,
        sections: list[dict[str, object]] | None = None,
        entry_point: int = 0x401000,
    ) -> None:
        self.path = path
        self.r2 = r2
        self.info = {"bin": {"baddr": entry_point}}
        self._sections = sections or []

    def get_sections(self) -> list[dict[str, object]]:
        return list(self._sections)


def test_get_entry_bytes_reads_hex_bytes() -> None:
    binary = _FakeBinary(r2=_FakeR2(entry_hex="414243"))

    assert get_entry_bytes(binary, 0x401000) == b"ABC"


def test_signature_confidence_accounts_for_matching_signals() -> None:
    signature = PackerSignature(
        name="TestPacker",
        packer_type=PackerType.UPX,
        entry_patterns=[b"ABC"],
        section_names=[".text"],
        string_patterns=["debugger"],
        entropy_threshold=7.0,
        confidence_threshold=0.5,
    )
    binary = _FakeBinary(
        r2=_FakeR2(entry_hex="414243", strings_output="debugger present"),
        sections=[{"name": ".text"}],
    )

    confidence = calculate_signature_confidence(
        signature,
        binary.get_sections(),
        get_entry_bytes(binary, 0x401000),
        binary,
        _FakeEntropyAnalyzer(7.5),
    )

    assert confidence == 1.0


def test_detect_packing_layers_reports_multiple_high_entropy_sections() -> None:
    sections = [
        {"name": ".packed1", "vaddr": 0x1000, "size": 16},
        {"name": ".packed2", "vaddr": 0x2000, "size": 16},
    ]
    binary = _FakeBinary(
        r2=_FakeR2(entry_hex="ff" * 16),
        sections=sections,
    )
    signatures = [
        PackerSignature(name="One", packer_type=PackerType.UPX, entropy_threshold=0.0, confidence_threshold=0.0),
        PackerSignature(name="Two", packer_type=PackerType.UPX, entropy_threshold=0.0, confidence_threshold=0.0),
    ]

    result = detect_packing_layers(signatures, binary, _FakeEntropyAnalyzer(0.0))

    assert result["requires_unpacking"] is True
    assert result["layers_detected"] >= 2
