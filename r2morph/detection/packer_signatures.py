"""
Packer signature database and detection for identifying known packers.

This module provides a database of packer signatures and methods
for detecting specific packers based on entry point patterns,
section names, strings, and entropy analysis.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from r2morph.utils.entropy import calculate_entropy

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

    def __init__(self):
        """Initialize the packer signature database."""
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> list[PackerSignature]:
        """Load known packer signatures."""
        signatures = []

        # VMProtect signatures (multiple versions)
        signatures.append(
            PackerSignature(
                name="VMProtect 3.x",
                packer_type=PackerType.VMPROTECT,
                entry_patterns=[
                    b"\x68\x00\x00\x00\x00\xe8\x00\x00\x00\x00",  # push 0; call
                    b"\xeb\x10\x53\x51\x52\x56\x57\x55",  # VMProtect entry stub
                    b"\x60\xbe\x00\x00\x41\x00\x8d\xbe\x00\xb0\xff\xff",  # VMProtect 2.x
                ],
                section_names=[".vmp0", ".vmp1", ".vmp2", ".vmp"],
                string_patterns=["VMProtect", "www.vmprotect.com", "PolyTech"],
                entropy_threshold=7.5,
                confidence_threshold=0.8,
            )
        )

        # Themida/WinLicense signatures
        signatures.append(
            PackerSignature(
                name="Themida/WinLicense",
                packer_type=PackerType.THEMIDA,
                entry_patterns=[
                    b"\x8b\xff\x55\x8b\xec\x6a\xff\x68",  # Themida entry
                    b"\x50\x53\x51\x52\x56\x57\x55\x8b",  # WinLicense entry
                    b"\xb8\x00\x00\x00\x00\x60\x0f\xc8",  # Themida 1.x
                    b"\x55\x8b\xec\x83\xec\x0c\x53\x56",  # WinLicense 2.x
                ],
                section_names=[".themida", ".winlice", ".tls", ".oreans"],
                import_patterns=["Themida", "WinLicense", "Oreans"],
                string_patterns=["Themida", "Oreans", "WinLicense", "www.oreans.com"],
                entropy_threshold=7.2,
                confidence_threshold=0.75,
            )
        )

        # Enigma Protector signatures
        signatures.append(
            PackerSignature(
                name="Enigma Protector",
                packer_type=PackerType.ENIGMA,
                entry_patterns=[
                    b"\x60\xe8\x00\x00\x00\x00\x5d\x50\x51\x52",  # Enigma entry
                    b"\xeb\x03\x5d\xeb\x05\xe8\xf8\xff\xff\xff",  # Enigma variant
                ],
                section_names=[".enigma1", ".enigma2", ".eng"],
                string_patterns=["Enigma", "The Enigma Protector"],
                entropy_threshold=7.0,
                confidence_threshold=0.8,
            )
        )

        # UPX signatures (multiple versions)
        signatures.append(
            PackerSignature(
                name="UPX",
                packer_type=PackerType.UPX,
                entry_patterns=[
                    b"\x60\xbe\x00\x10\x40\x00\x8d\xbe\x00\xf0\xff\xff",  # UPX 0.xx
                    b"\x83\x7c\x24\x08\x01\x0f\x85\x95\x01\x00\x00",  # UPX 1.xx
                    b"\x60\xbe\x00\x00\x41\x00\x8d\xbe\x00\xb0\xff\xff",  # UPX 2.xx
                ],
                section_names=["UPX0", "UPX1", "UPX!", ".upx0", ".upx1"],
                string_patterns=["UPX!", "$Id: UPX", "upx394w"],
                entropy_threshold=6.5,
                confidence_threshold=0.9,
            )
        )

        # ASPack signatures
        signatures.append(
            PackerSignature(
                name="ASPack",
                packer_type=PackerType.ASPACK,
                entry_patterns=[
                    b"\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04\x5d\x45\x55",  # ASPack 1.x
                    b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed\x96\x78\x43\x00",  # ASPack 2.x
                ],
                section_names=[".aspack", ".adata"],
                string_patterns=["ASPack", "www.aspack.com"],
                entropy_threshold=6.8,
                confidence_threshold=0.85,
            )
        )

        # PECompact signatures
        signatures.append(
            PackerSignature(
                name="PECompact",
                packer_type=PackerType.PECOMPACT,
                entry_patterns=[
                    b"\xeb\x06\x68\x00\x00\x00\x00\xc3\x9c\x60\x8b\x74",  # PECompact 1.x
                    b"\x8b\x04\x24\x01\x05\x8b\x1c\x24\x01\x1d",  # PECompact 2.x
                ],
                section_names=[".pec1", ".pec2", ".pec"],
                string_patterns=["PECompact2", "Bitsum LLC"],
                entropy_threshold=7.1,
                confidence_threshold=0.8,
            )
        )

        # MPRESS signatures
        signatures.append(
            PackerSignature(
                name="MPRESS",
                packer_type=PackerType.MPRESS,
                entry_patterns=[
                    b"\x60\xe8\x00\x00\x00\x00\x58\x05\x5a\x0a\x00\x00",  # MPRESS 1.x
                    b"\x60\xe8\x00\x00\x00\x00\x58\x05\x4a\x0a\x00\x00",  # MPRESS 2.x
                ],
                section_names=[".mpress1", ".mpress2"],
                string_patterns=["MPRESS", "mpress"],
                entropy_threshold=6.9,
                confidence_threshold=0.8,
            )
        )

        # ASProtect signatures
        signatures.append(
            PackerSignature(
                name="ASProtect",
                packer_type=PackerType.ASPROTECT,
                entry_patterns=[
                    b"\x68\x01\x00\x00\x00\xe8\x01\x00\x00\x00\xc3\xc3",  # ASProtect 1.x
                    b"\x90\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04\x5d\x45",  # ASProtect 2.x
                ],
                section_names=[".aspr", ".asprotect"],
                string_patterns=["ASProtect", "www.aspack.com"],
                entropy_threshold=7.3,
                confidence_threshold=0.75,
            )
        )

        # Obsidium signatures
        signatures.append(
            PackerSignature(
                name="Obsidium",
                packer_type=PackerType.OBSIDIUM,
                entry_patterns=[
                    b"\xeb\x02\xe8\x25\xeb\x03\xe9\xeb\x04\x40\xeb\x08",  # Obsidium 1.x
                    b"\xeb\x01\x90\xeb\x02\xeb\x01\xeb\x05\xe8\x01\x00",  # Obsidium 2.x
                ],
                section_names=[".obsidium", ".obfus"],
                string_patterns=["Obsidium", "www.obsidium.de"],
                entropy_threshold=7.4,
                confidence_threshold=0.8,
            )
        )

        # Armadillo signatures
        signatures.append(
            PackerSignature(
                name="Armadillo",
                packer_type=PackerType.ARMADILLO,
                entry_patterns=[
                    b"\x55\x8b\xec\x6a\xff\x68\x00\x00\x00\x00\x68",  # Armadillo entry
                ],
                section_names=[".arma", ".armadill"],
                string_patterns=["Armadillo", "Silicon Realms"],
                entropy_threshold=6.7,
                confidence_threshold=0.75,
            )
        )

        # SafeEngine signatures
        signatures.append(
            PackerSignature(
                name="SafeEngine",
                packer_type=PackerType.SAFENGINE,
                entry_patterns=[
                    b"\x60\xe8\x00\x00\x00\x00\x5d\x50\x51\x52\x53",  # SafeEngine entry
                ],
                section_names=[".seau", ".seau1", ".seau2"],
                string_patterns=["SafeEngine"],
                entropy_threshold=7.2,
                confidence_threshold=0.8,
            )
        )

        # PESpin signatures
        signatures.append(
            PackerSignature(
                name="PESpin",
                packer_type=PackerType.PESPIN,
                entry_patterns=[
                    b"\xeb\x01\x68\x60\xe8\x00\x00\x00\x00\x8b\x1c\x24",  # PESpin 1.x
                ],
                section_names=[".pespin"],
                string_patterns=["PESpin", "Cyberbob"],
                entropy_threshold=6.8,
                confidence_threshold=0.8,
            )
        )

        # Metamorphic engine detection
        signatures.append(
            PackerSignature(
                name="Metamorphic Engine",
                packer_type=PackerType.METAMORPHIC,
                entry_patterns=[
                    # Generic metamorphic patterns - highly variable
                    b"\x90\x90\x90\x90\xeb",  # NOPs + variable jump prefix
                    b"\x83\xc0\x00\x83\xe8\x00",  # Dead arithmetic
                ],
                section_names=[".meta", ".morph", ".poly"],
                string_patterns=["metamorph", "polymorphic"],
                entropy_threshold=5.5,  # Lower threshold for metamorphic
                confidence_threshold=0.6,
            )
        )

        return signatures

    def detect(self, binary: "Binary", entropy_analyzer: "EntropyAnalyzer") -> PackerType:
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
            # Get binary information
            sections = binary.get_sections()
            entry_point = binary.info.get("bin", {}).get("baddr", 0)

            # Read entry point bytes
            entry_bytes = self._get_entry_bytes(binary, entry_point)

            # Check each signature
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

    def _get_entry_bytes(self, binary: "Binary", entry_point: int, size: int = 32) -> bytes:
        """Get bytes at entry point."""
        try:
            entry_hex = binary.r2.cmd(f"p8 {size} @ {entry_point}")
            return bytes.fromhex(entry_hex.strip()) if entry_hex.strip() else b""
        except Exception:
            return b""

    def _calculate_signature_confidence(
        self,
        signature: PackerSignature,
        sections: list[dict[str, Any]],
        entry_bytes: bytes,
        binary: "Binary",
        entropy_analyzer: "EntropyAnalyzer",
    ) -> float:
        """Calculate confidence score for a packer signature."""
        confidence = 0.0
        total_checks = 0

        # Check section names
        if signature.section_names:
            section_names = [s.get("name", "") for s in sections]
            for sig_section in signature.section_names:
                total_checks += 1
                if any(sig_section in name for name in section_names):
                    confidence += 1.0

        # Check entry point patterns
        if signature.entry_patterns and entry_bytes:
            for pattern in signature.entry_patterns:
                total_checks += 1
                if pattern in entry_bytes:
                    confidence += 1.0

        # Check strings
        if signature.string_patterns:
            try:
                strings_output = binary.r2.cmd("izz")
                for pattern in signature.string_patterns:
                    total_checks += 1
                    if pattern.lower() in strings_output.lower():
                        confidence += 1.0
            except Exception:
                pass

        # Check entropy
        entropy_result = entropy_analyzer.analyze_file(Path(binary.path))
        if entropy_result.overall_entropy >= signature.entropy_threshold:
            total_checks += 1
            confidence += 1.0

        return confidence / max(total_checks, 1)

    def detect_packing_layers(self, binary: "Binary", entropy_analyzer: "EntropyAnalyzer") -> dict[str, Any]:
        """
        Detect multiple packing layers.

        Args:
            binary: Binary to analyze
            entropy_analyzer: EntropyAnalyzer instance

        Returns:
            Dictionary with layer analysis
        """
        result = {
            "layers_detected": 0,
            "packers": [],
            "confidence": 0.0,
            "requires_unpacking": False,
        }

        try:
            # Analyze entropy across sections
            sections = binary.get_sections()
            high_entropy_sections = []

            for section in sections:
                if section.get("size", 0) > 0:
                    # Get section data and calculate entropy
                    addr = section.get("vaddr", 0)
                    size = min(section.get("size", 0), 1024)  # Limit for performance

                    try:
                        data_hex = binary.r2.cmd(f"p8 {size} @ {addr}")
                        if data_hex and data_hex.strip():
                            data = bytes.fromhex(data_hex.strip())
                            entropy = self._calculate_entropy(data)

                            if entropy > 7.0:  # High entropy threshold
                                high_entropy_sections.append(
                                    {"name": section.get("name", ""), "entropy": entropy, "size": size}
                                )
                    except Exception:
                        continue

            # Multiple high-entropy sections suggest layered packing
            if len(high_entropy_sections) > 1:
                result["layers_detected"] = len(high_entropy_sections)
                result["requires_unpacking"] = True
                result["confidence"] = min(1.0, len(high_entropy_sections) / 5.0)

            # Check for nested packer signatures
            sections_list = binary.get_sections()
            entry_bytes = self._get_entry_bytes(binary, binary.info.get("bin", {}).get("baddr", 0))

            for signature in self.signatures:
                confidence = self._calculate_signature_confidence(
                    signature, sections_list, entry_bytes, binary, entropy_analyzer
                )

                if confidence > 0.5:
                    result["packers"].append(
                        {"name": signature.name, "type": signature.packer_type.value, "confidence": confidence}
                    )

            # If multiple packers detected, likely layered
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
