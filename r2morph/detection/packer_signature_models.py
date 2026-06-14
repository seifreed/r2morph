"""Model types for packer signature detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


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
