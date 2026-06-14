"""
Packer signature database and detection for identifying known packers.

This module provides a database of packer signatures and methods
for detecting specific packers based on entry point patterns,
section names, strings, and entropy analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from r2morph.detection.packer_signature_catalogs import (
    compressor_signatures,
    other_signatures,
    protector_signatures,
    vm_protector_signatures,
)
from r2morph.utils.entropy import calculate_entropy

if TYPE_CHECKING:
    from r2morph.core.binary import Binary
    from r2morph.detection.entropy_analyzer import EntropyAnalyzer

logger = logging.getLogger(__name__)


class PackerType(Enum):
    """Known packer and obfuscator types."""

    # Commercial VM-based packers
    VMPROTECT = "vmprotect"
    THEMIDA = "themida"
    WINLICENSE = "winlicense"
    ENIGMA = "enigma"
    OBSIDIUM = "obsidium"
    SAFENGINE = "safengine"
    VPROTECT = "vprotect"

    # Traditional packers
    UPX = "upx"
    ASPACK = "aspack"
    PECOMPACT = "pecompact"
    MPRESS = "mpress"
    PACKMAN = "packman"
    NSPACK = "nspack"
    RLPACK = "rlpack"
    PESPIN = "pespin"

    # Protection systems
    ASPROTECT = "asprotect"
    ARMADILLO = "armadillo"
    EXECRYPTOR = "execryptor"
    PKLITE = "pklite"
    WWPACK = "wwpack"

    # Custom/Unknown
    CUSTOM_VM = "custom_vm"
    CUSTOM_PACKER = "custom_packer"
    METAMORPHIC = "metamorphic"
    UNKNOWN = "unknown"
    NONE = "none"


@dataclass
class PackerSignature:
    """Signature for identifying specific packers."""

    name: str
    packer_type: PackerType
    entry_patterns: list[bytes] = field(default_factory=list)
    section_names: list[str] = field(default_factory=list)
    import_patterns: list[str] = field(default_factory=list)
    string_patterns: list[str] = field(default_factory=list)
    entropy_threshold: float = 7.0
    confidence_threshold: float = 0.7


class PackerSignatureDatabase:
    """
    Database of packer signatures for detection.

    Provides methods for loading signatures and detecting
    packers in binaries based on multiple heuristics.
    """

    def __init__(self) -> None:
        """Initialize the packer signature database."""
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> list[PackerSignature]:
        """Load known packer signatures from categorized sub-loaders."""
        return [
            *vm_protector_signatures(),
            *compressor_signatures(),
            *protector_signatures(),
            *other_signatures(),
        ]

    def detect(self, binary: Binary, entropy_analyzer: EntropyAnalyzer) -> PackerType:
        """
        Detect specific packer type using signatures.

        Args:
            binary: Binary to analyze
            entropy_analyzer: EntropyAnalyzer instance for entropy checks

        Returns:
            Detected packer type
        """
        logger.debug("Detecting packer type")

        best_match = PackerType.NONE
        best_confidence = 0.0

        try:
            sections = binary.get_sections()
            entry_point = binary.info.get("bin", {}).get("baddr", 0)
            entry_bytes = self._get_entry_bytes(binary, entry_point)

            for signature in self.signatures:
                confidence = self._calculate_signature_confidence(
                    signature, sections, entry_bytes, binary, entropy_analyzer
                )

                if confidence > best_confidence and confidence >= signature.confidence_threshold:
                    best_confidence = confidence
                    best_match = signature.packer_type

            if best_match != PackerType.NONE:
                logger.info(f"Detected packer: {best_match.value} (confidence: {best_confidence:.2f})")

        except Exception as e:
            logger.error(f"Error detecting packer: {e}")

        return best_match

    def _get_entry_bytes(self, binary: Binary, entry_point: int, size: int = 32) -> bytes:
        """Get bytes at entry point."""
        try:
            if binary.r2 is None:
                return b""
            entry_hex = binary.r2.cmd(f"p8 {size} @ {entry_point}")
            return bytes.fromhex(entry_hex.strip()) if entry_hex.strip() else b""
        except Exception:
            return b""

    def _calculate_signature_confidence(
        self,
        signature: PackerSignature,
        sections: list[dict[str, Any]],
        entry_bytes: bytes,
        binary: Binary,
        entropy_analyzer: EntropyAnalyzer,
    ) -> float:
        """Calculate confidence score for a packer signature."""
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

    def detect_packing_layers(self, binary: Binary, entropy_analyzer: EntropyAnalyzer) -> dict[str, Any]:
        """
        Detect multiple packing layers.

        Args:
            binary: Binary to analyze
            entropy_analyzer: EntropyAnalyzer instance

        Returns:
            Dictionary with layer analysis
        """
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
                    size = min(section.get("size", 0), 1024)  # Limit for performance

                    try:
                        if binary.r2 is None:
                            continue
                        data_hex = binary.r2.cmd(f"p8 {size} @ {addr}")
                        if data_hex and data_hex.strip():
                            data = bytes.fromhex(data_hex.strip())
                            entropy = self._calculate_entropy(data)

                            if entropy > 7.0:  # High entropy threshold
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
            entry_bytes = self._get_entry_bytes(binary, binary.info.get("bin", {}).get("baddr", 0))

            for signature in self.signatures:
                confidence = self._calculate_signature_confidence(
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

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data.

        Delegates to shared utility in r2morph.utils.entropy.
        """
        return calculate_entropy(data)
