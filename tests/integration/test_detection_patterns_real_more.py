from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.control_flow_detector import ControlFlowAnalyzer
from r2morph.detection.packer_signatures import PackerSignatureDatabase, PackerType
from r2morph.detection.pattern_matcher import PatternMatcher
from r2morph.detection.entropy_analyzer import EntropyAnalyzer


def test_pattern_matcher_scans_strings_and_imports(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "pattern_sample.bin"
    work_path.write_bytes(source.read_bytes() + b"IsDebuggerPresent\\x00vmware\\x00")

    with Binary(work_path) as binary:
        binary.analyze()
        matcher = PatternMatcher(binary)
        result = matcher.scan()

    assert isinstance(result.anti_debug_detected, bool)
    assert isinstance(result.anti_vm_detected, bool)
    assert isinstance(result.import_hiding_detected, bool)
    assert "IsDebuggerPresent" in result.anti_debug_apis
    assert any("vmware" in item.lower() for item in result.anti_vm_artifacts)


def test_pattern_matcher_find_patterns_and_search_strings(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "pattern_bytes.bin"
    payload = source.read_bytes() + b"r2morph_test_marker\\x00"
    work_path.write_bytes(payload)

    marker = b"r2morphXX"

    with Binary(work_path, writable=True) as binary:
        binary.analyze()
        sections = binary.get_sections()
        assert sections
        candidates = [
            section for section in sections
            if int(section.get("vaddr", 0) or 0) > 0
            and int(section.get("size", 0) or 0) >= len(marker)
        ]
        assert candidates
        section = candidates[0]
        vaddr = int(section.get("vaddr", 0) or 0)
        paddr = int(section.get("paddr", 0) or 0)
        assert binary.write_bytes(vaddr, marker) is True
        binary.r2.cmd("e search.in=io.maps")
        matcher = PatternMatcher(binary)
        results = matcher.find_patterns([marker])
        string_hits = matcher.search_strings([marker.decode(), "not_there"])

    if paddr > 0:
        assert work_path.read_bytes()[paddr : paddr + len(marker)] == marker
    assert marker in results
    assert string_hits[marker.decode()] is True
    assert string_hits["not_there"] is False


def test_control_flow_analyzer_real_basic(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "cff_sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path) as binary:
        binary.analyze()
        analyzer = ControlFlowAnalyzer(binary)
        result = analyzer.analyze()

    assert result.cff_confidence >= 0.0
    assert result.opaque_predicates_count >= 0
    assert result.mba_expressions_count >= 0
    assert result.vm_handler_count >= 0
    assert result.polymorphic_ratio >= 0.0


def test_packer_signature_detection_paths(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "packer_sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path) as binary:
        binary.analyze()
        entropy = EntropyAnalyzer()
        db = PackerSignatureDatabase()
        detected = db.detect(binary, entropy)
        layers = db.detect_packing_layers(binary, entropy)

    assert isinstance(detected, PackerType)
    assert isinstance(layers, dict)
    assert "layers_detected" in layers
