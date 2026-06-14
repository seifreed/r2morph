"""Helper functions for packer signature scoring and layer analysis."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from r2morph.detection.packer_signature_models import PackerSignature
from r2morph.utils.entropy import calculate_entropy

if TYPE_CHECKING:
    from r2morph.core.binary import Binary
    from r2morph.detection.entropy_analyzer import EntropyAnalyzer

logger = logging.getLogger(__name__)


def get_entry_bytes(binary: Binary, entry_point: int, size: int = 32) -> bytes:
    """Read bytes at the entry point."""
    try:
        if binary.r2 is None:
            return b""
        entry_hex = binary.r2.cmd(f"p8 {size} @ {entry_point}")
        return bytes.fromhex(entry_hex.strip()) if entry_hex.strip() else b""
    except Exception:
        return b""


def calculate_signature_confidence(
    signature: PackerSignature,
    sections: list[dict[str, Any]],
    entry_bytes: bytes,
    binary: Binary,
    entropy_analyzer: EntropyAnalyzer,
) -> float:
    """Calculate confidence for one packer signature."""
    confidence = 0.0
    total_checks = 0

    if signature.section_names:
        section_names = [s.get("name", "") for s in sections]
        for sig_section in signature.section_names:
            total_checks += 1
            if any(sig_section in name for name in section_names):
                confidence += 1.0

    if signature.entry_patterns and entry_bytes:
        for pattern in signature.entry_patterns:
            total_checks += 1
            if pattern in entry_bytes:
                confidence += 1.0

    if signature.string_patterns:
        try:
            strings_output = binary.r2.cmd("izz") if binary.r2 is not None else ""
            for str_pattern in signature.string_patterns:
                total_checks += 1
                if str_pattern.lower() in strings_output.lower():
                    confidence += 1.0
        except Exception as e:
            logger.debug(f"Failed to check string patterns: {e}")

    entropy_result = entropy_analyzer.analyze_file(Path(binary.path))
    if entropy_result.overall_entropy >= signature.entropy_threshold:
        total_checks += 1
        confidence += 1.0

    return confidence / max(total_checks, 1)


def detect_packing_layers(
    signatures: list[PackerSignature],
    binary: Binary,
    entropy_analyzer: EntropyAnalyzer,
) -> dict[str, Any]:
    """Detect whether a binary likely contains multiple packing layers."""
    result: dict[str, Any] = {
        "layers_detected": 0,
        "packers": [],
        "confidence": 0.0,
        "requires_unpacking": False,
    }

    try:
        sections = binary.get_sections()
        high_entropy_sections = []

        for section in sections:
            if section.get("size", 0) > 0:
                addr = section.get("vaddr", 0)
                size = min(section.get("size", 0), 1024)

                try:
                    if binary.r2 is None:
                        continue
                    data_hex = binary.r2.cmd(f"p8 {size} @ {addr}")
                    if data_hex and data_hex.strip():
                        data = bytes.fromhex(data_hex.strip())
                        entropy = calculate_entropy(data)

                        if entropy > 7.0:
                            high_entropy_sections.append(
                                {
                                    "name": section.get("name", ""),
                                    "entropy": entropy,
                                    "size": size,
                                }
                            )
                except Exception as e:
                    logger.debug(f"Failed to analyze section entropy: {e}")
                    continue

        if len(high_entropy_sections) > 1:
            result["layers_detected"] = len(high_entropy_sections)
            result["requires_unpacking"] = True
            result["confidence"] = min(1.0, len(high_entropy_sections) / 5.0)

        sections_list = binary.get_sections()
        entry_bytes = get_entry_bytes(binary, binary.info.get("bin", {}).get("baddr", 0))

        for signature in signatures:
            confidence = calculate_signature_confidence(
                signature, sections_list, entry_bytes, binary, entropy_analyzer
            )

            if confidence > 0.5:
                result["packers"].append(
                    {
                        "name": signature.name,
                        "type": signature.packer_type.value,
                        "confidence": confidence,
                    }
                )

        if len(result["packers"]) > 1:
            result["layers_detected"] = max(result["layers_detected"], len(result["packers"]))
            result["requires_unpacking"] = True

    except Exception as e:
        logger.error(f"Layer detection failed: {e}")

    return result
