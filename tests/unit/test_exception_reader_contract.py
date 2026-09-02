import struct

from r2morph.analysis.exception_models import ExceptionAction
from r2morph.analysis.exception_reader import ExceptionInfoReader
from tests._doubles.in_memory_pe_pdata_binary import InMemoryPEPdataBinary
from tests.utils.assertions import expect

_EH_FRAME_ADDRESS = 0x7000
_LSDA_ADDRESS = 0x8000
_FUNCTION_ADDRESS = 0x401000


class _InMemoryElfExceptionBinary:
    def __init__(self) -> None:
        self._eh_frame = self._build_eh_frame()
        self._lsda = bytes((0xFF, 0xFF, 0x01, 0x04, 0x00, 0x04, 0x08, 0x01, 0x01, 0x00))

    def get_arch_info(self) -> dict[str, int | str]:
        return {"format": "ELF64", "bits": 64}

    def get_sections(self) -> list[dict[str, int | str]]:
        return [
            {"name": ".eh_frame", "addr": _EH_FRAME_ADDRESS, "size": len(self._eh_frame)},
            {"name": ".gcc_except_table", "addr": _LSDA_ADDRESS, "size": len(self._lsda)},
        ]

    def read_bytes(self, address: int, size: int) -> bytes:
        if address == _EH_FRAME_ADDRESS:
            return self._eh_frame[:size]
        if address == _LSDA_ADDRESS:
            return self._lsda[:size]
        return b""

    @staticmethod
    def _entry(body: bytes) -> bytes:
        return struct.pack("<I", len(body)) + body

    @classmethod
    def _build_eh_frame(cls) -> bytes:
        cie_body = struct.pack("<I", 0) + b"\x01zPLR\x00" + b"\x01\x78\x10" + bytes((3, 0xFF, 0x1B, 0x1B))
        cie = cls._entry(cie_body)
        fde_start = len(cie)
        cie_pointer = fde_start + 4
        initial_field = _EH_FRAME_ADDRESS + fde_start + 8
        initial_delta = _FUNCTION_ADDRESS - initial_field
        lsda_field = _EH_FRAME_ADDRESS + fde_start + 17
        lsda_delta = _LSDA_ADDRESS - lsda_field
        fde_body = (
            struct.pack("<I", cie_pointer)
            + struct.pack("<i", initial_delta)
            + struct.pack("<i", 0x40)
            + bytes((4,))
            + struct.pack("<i", lsda_delta)
        )
        return cie + cls._entry(fde_body) + b"\x00\x00\x00\x00"

    @staticmethod
    def _entry64(body: bytes) -> bytes:
        return struct.pack("<I", 0xFFFFFFFF) + struct.pack("<Q", len(body)) + body

    @classmethod
    def _build_dwarf64_eh_frame(cls) -> bytes:
        cie_body = struct.pack("<Q", 0) + b"\x01zPLR\x00" + b"\x01\x78\x10" + bytes((3, 0xFF, 0x1B, 0x1B))
        cie = cls._entry64(cie_body)
        fde_start = len(cie)
        cie_pointer = fde_start + 12
        initial_field = _EH_FRAME_ADDRESS + fde_start + 20
        initial_delta = _FUNCTION_ADDRESS - initial_field
        lsda_field = _EH_FRAME_ADDRESS + fde_start + 29
        lsda_delta = _LSDA_ADDRESS - lsda_field
        fde_body = (
            struct.pack("<Q", cie_pointer)
            + struct.pack("<i", initial_delta)
            + struct.pack("<i", 0x40)
            + bytes((4,))
            + struct.pack("<i", lsda_delta)
        )
        return cie + cls._entry64(fde_body) + b"\x00\x00\x00\x00"


class _InMemoryR2VaddrElfExceptionBinary(_InMemoryElfExceptionBinary):
    def get_sections(self) -> list[dict[str, int | str]]:
        return [
            {"name": ".eh_frame", "vaddr": _EH_FRAME_ADDRESS, "size": len(self._eh_frame)},
            {"name": ".gcc_except_table", "vaddr": _LSDA_ADDRESS, "size": len(self._lsda)},
        ]


class _InMemoryDwarf64ExceptionBinary(_InMemoryElfExceptionBinary):
    def __init__(self) -> None:
        super().__init__()
        self._eh_frame = self._build_dwarf64_eh_frame()


def _packed_entry(begin: int, function_length_units: int) -> bytes:
    second = 0x1 | ((function_length_units & 0x7FF) << 2)
    return struct.pack("<II", begin, second)


def test_exception_reader_parses_pe_pdata_entries() -> None:
    pdata = _packed_entry(0x1000, 0x10) + _packed_entry(0x2000, 0x08)
    binary = InMemoryPEPdataBinary(
        bits=32,
        pdata_addr=0x4000,
        pdata_declared_size=len(pdata),
        pdata_bytes=pdata,
    )

    frames = ExceptionInfoReader(binary).read_exception_frames()

    expect(set(frames) == {4096, 8192})
    expect(frames[4096].function_end == 4096 + 16 * 2)
    expect(frames[8192].function_end == 8192 + 8 * 2)


def test_exception_reader_decodes_elf_fde_lsda_and_landing_pad() -> None:
    frames = ExceptionInfoReader(_InMemoryElfExceptionBinary()).read_exception_frames()

    frame = frames[_FUNCTION_ADDRESS]
    expect(frame.function_end == _FUNCTION_ADDRESS + 0x40)
    expect(frame.lsda_address == _LSDA_ADDRESS)
    expect(len(frame.landing_pads) == 1)


def test_exception_reader_accepts_radare2_vaddr_sections() -> None:
    frames = ExceptionInfoReader(_InMemoryR2VaddrElfExceptionBinary()).read_exception_frames()

    expect(frames[_FUNCTION_ADDRESS].lsda_address == _LSDA_ADDRESS)


def test_exception_reader_classifies_elf_landing_pad_action_as_catch() -> None:
    frames = ExceptionInfoReader(_InMemoryElfExceptionBinary()).read_exception_frames()

    expect(frames[_FUNCTION_ADDRESS].landing_pads[0].address == _FUNCTION_ADDRESS + 8)
    expect(frames[_FUNCTION_ADDRESS].landing_pads[0].action == ExceptionAction.CATCH)


def test_exception_reader_parses_dwarf64_eh_frame_fde_and_landing_pad() -> None:
    frames = ExceptionInfoReader(_InMemoryDwarf64ExceptionBinary()).read_exception_frames()

    frame = frames[_FUNCTION_ADDRESS]
    expect(
        (frame.function_end, frame.lsda_address, len(frame.landing_pads))
        == (_FUNCTION_ADDRESS + 0x40, _LSDA_ADDRESS, 1)
    )
