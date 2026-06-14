"""
Packer signature database and detection for identifying known packers.

This module provides a database of packer signatures and methods
for detecting specific packers based on entry point patterns,
section names, strings, and entropy analysis.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from r2morph.detection.packer_signature_analysis import (
    calculate_signature_confidence,
    detect_packing_layers,
    get_entry_bytes,
)
from r2morph.detection.packer_signature_catalogs import (
    compressor_signatures,
    other_signatures,
    protector_signatures,
    vm_protector_signatures,
)
from r2morph.detection.packer_signature_models import PackerSignature, PackerType

if TYPE_CHECKING:
    from r2morph.core.binary import Binary
    from r2morph.detection.entropy_analyzer import EntropyAnalyzer

logger = logging.getLogger(__name__)


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
            entry_bytes = get_entry_bytes(binary, entry_point)

            for signature in self.signatures:
                confidence = calculate_signature_confidence(signature, sections, entry_bytes, binary, entropy_analyzer)

                if confidence > best_confidence and confidence >= signature.confidence_threshold:
                    best_confidence = confidence
                    best_match = signature.packer_type

            if best_match != PackerType.NONE:
                logger.info(f"Detected packer: {best_match.value} (confidence: {best_confidence:.2f})")

        except Exception as e:
            logger.error(f"Error detecting packer: {e}")

        return best_match

    def detect_packing_layers(self, binary: Binary, entropy_analyzer: EntropyAnalyzer) -> dict[str, Any]:
        """
        Detect multiple packing layers.

        Args:
            binary: Binary to analyze
            entropy_analyzer: EntropyAnalyzer instance

        Returns:
            Dictionary with layer analysis
        """
        return detect_packing_layers(self.signatures, binary, entropy_analyzer)
