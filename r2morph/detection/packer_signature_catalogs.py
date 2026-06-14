"""Static packer signature catalogs."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from r2morph.detection.packer_signatures import PackerSignature


def vm_protector_signatures() -> list[PackerSignature]:
    from r2morph.detection.packer_signatures import PackerSignature, PackerType

    return [
        PackerSignature(
            name="VMProtect 3.x",
            packer_type=PackerType.VMPROTECT,
            entry_patterns=[
                b"\x68\x00\x00\x00\x00\xe8\x00\x00\x00\x00",
                b"\xeb\x10\x53\x51\x52\x56\x57\x55",
                b"\x60\xbe\x00\x00\x41\x00\x8d\xbe\x00\xb0\xff\xff",
            ],
            section_names=[".vmp0", ".vmp1", ".vmp2", ".vmp"],
            string_patterns=["VMProtect", "www.vmprotect.com", "PolyTech"],
            entropy_threshold=7.5,
            confidence_threshold=0.8,
        ),
        PackerSignature(
            name="Themida/WinLicense",
            packer_type=PackerType.THEMIDA,
            entry_patterns=[
                b"\x8b\xff\x55\x8b\xec\x6a\xff\x68",
                b"\x50\x53\x51\x52\x56\x57\x55\x8b",
                b"\xb8\x00\x00\x00\x00\x60\x0f\xc8",
                b"\x55\x8b\xec\x83\xec\x0c\x53\x56",
            ],
            section_names=[".themida", ".winlice", ".tls", ".oreans"],
            import_patterns=["Themida", "WinLicense", "Oreans"],
            string_patterns=["Themida", "Oreans", "WinLicense", "www.oreans.com"],
            entropy_threshold=7.2,
            confidence_threshold=0.75,
        ),
        PackerSignature(
            name="Enigma Protector",
            packer_type=PackerType.ENIGMA,
            entry_patterns=[
                b"\x60\xe8\x00\x00\x00\x00\x5d\x50\x51\x52",
                b"\xeb\x03\x5d\xeb\x05\xe8\xf8\xff\xff\xff",
            ],
            section_names=[".enigma1", ".enigma2", ".eng"],
            string_patterns=["Enigma", "The Enigma Protector"],
            entropy_threshold=7.0,
            confidence_threshold=0.8,
        ),
    ]


def compressor_signatures() -> list[PackerSignature]:
    from r2morph.detection.packer_signatures import PackerSignature, PackerType

    return [
        PackerSignature(
            name="UPX",
            packer_type=PackerType.UPX,
            entry_patterns=[
                b"\x60\xbe\x00\x10\x40\x00\x8d\xbe\x00\xf0\xff\xff",
                b"\x83\x7c\x24\x08\x01\x0f\x85\x95\x01\x00\x00",
                b"\x60\xbe\x00\x00\x41\x00\x8d\xbe\x00\xb0\xff\xff",
            ],
            section_names=["UPX0", "UPX1", "UPX!", ".upx0", ".upx1"],
            string_patterns=["UPX!", "$Id: UPX", "upx394w"],
            entropy_threshold=6.5,
            confidence_threshold=0.9,
        ),
        PackerSignature(
            name="ASPack",
            packer_type=PackerType.ASPACK,
            entry_patterns=[
                b"\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04\x5d\x45\x55",
                b"\x60\xe8\x00\x00\x00\x00\x5d\x81\xed\x96\x78\x43\x00",
            ],
            section_names=[".aspack", ".adata"],
            string_patterns=["ASPack", "www.aspack.com"],
            entropy_threshold=6.8,
            confidence_threshold=0.85,
        ),
        PackerSignature(
            name="PECompact",
            packer_type=PackerType.PECOMPACT,
            entry_patterns=[
                b"\xeb\x06\x68\x00\x00\x00\x00\xc3\x9c\x60\x8b\x74",
                b"\x8b\x04\x24\x01\x05\x8b\x1c\x24\x01\x1d",
            ],
            section_names=[".pec1", ".pec2", ".pec"],
            string_patterns=["PECompact2", "Bitsum LLC"],
            entropy_threshold=7.1,
            confidence_threshold=0.8,
        ),
        PackerSignature(
            name="MPRESS",
            packer_type=PackerType.MPRESS,
            entry_patterns=[
                b"\x60\xe8\x00\x00\x00\x00\x58\x05\x5a\x0a\x00\x00",
                b"\x60\xe8\x00\x00\x00\x00\x58\x05\x4a\x0a\x00\x00",
            ],
            section_names=[".mpress1", ".mpress2"],
            string_patterns=["MPRESS", "mpress"],
            entropy_threshold=6.9,
            confidence_threshold=0.8,
        ),
    ]


def protector_signatures() -> list[PackerSignature]:
    from r2morph.detection.packer_signatures import PackerSignature, PackerType

    return [
        PackerSignature(
            name="ASProtect",
            packer_type=PackerType.ASPROTECT,
            entry_patterns=[
                b"\x68\x01\x00\x00\x00\xe8\x01\x00\x00\x00\xc3\xc3",
                b"\x90\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04\x5d\x45",
            ],
            section_names=[".aspr", ".asprotect"],
            string_patterns=["ASProtect", "www.aspack.com"],
            entropy_threshold=7.3,
            confidence_threshold=0.75,
        ),
        PackerSignature(
            name="Obsidium",
            packer_type=PackerType.OBSIDIUM,
            entry_patterns=[
                b"\xeb\x02\xe8\x25\xeb\x03\xe9\xeb\x04\x40\xeb\x08",
                b"\xeb\x01\x90\xeb\x02\xeb\x01\xeb\x05\xe8\x01\x00",
            ],
            section_names=[".obsidium", ".obfus"],
            string_patterns=["Obsidium", "www.obsidium.de"],
            entropy_threshold=7.4,
            confidence_threshold=0.8,
        ),
        PackerSignature(
            name="Armadillo",
            packer_type=PackerType.ARMADILLO,
            entry_patterns=[
                b"\x55\x8b\xec\x6a\xff\x68\x00\x00\x00\x00\x68",
            ],
            section_names=[".arma", ".armadill"],
            string_patterns=["Armadillo", "Silicon Realms"],
            entropy_threshold=6.7,
            confidence_threshold=0.75,
        ),
        PackerSignature(
            name="SafeEngine",
            packer_type=PackerType.SAFENGINE,
            entry_patterns=[
                b"\x60\xe8\x00\x00\x00\x00\x5d\x50\x51\x52\x53",
            ],
            section_names=[".seau", ".seau1", ".seau2"],
            string_patterns=["SafeEngine"],
            entropy_threshold=7.2,
            confidence_threshold=0.8,
        ),
    ]


def other_signatures() -> list[PackerSignature]:
    from r2morph.detection.packer_signatures import PackerSignature, PackerType

    return [
        PackerSignature(
            name="PESpin",
            packer_type=PackerType.PESPIN,
            entry_patterns=[b"\xeb\x01\x68\x60\xe8\x00\x00\x00\x00\x8b\x1c\x24"],
            section_names=[".pespin"],
            string_patterns=["PESpin", "Cyberbob"],
            entropy_threshold=6.8,
            confidence_threshold=0.8,
        ),
        PackerSignature(
            name="Metamorphic Engine",
            packer_type=PackerType.METAMORPHIC,
            entry_patterns=[
                b"\x90\x90\x90\x90\xeb",
                b"\x83\xc0\x00\x83\xe8\x00",
            ],
            section_names=[".meta", ".morph", ".poly"],
            string_patterns=["metamorph", "polymorphic"],
            entropy_threshold=5.5,
            confidence_threshold=0.6,
        ),
    ]


__all__ = [
    "compressor_signatures",
    "other_signatures",
    "protector_signatures",
    "vm_protector_signatures",
]
