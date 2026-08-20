from r2morph.analysis.exception_models import (
    ExceptionAction,
    ExceptionFrame,
    ExceptionTableEntry,
    LandingPad,
)
from tests.utils.assertions import expect

_EXPECTED_ENTRY_LANDING_PAD_4198416 = 0x401010
_EXPECTED_FRAME_LANDING_PADS_0_ADDRESS_4198416 = 0x401010


def test_exception_models_contract() -> None:
    pad = LandingPad(address=0x401010, size=16, action=ExceptionAction.CATCH)
    entry = ExceptionTableEntry(
        start_address=0x401000,
        end_address=0x401020,
        landing_pad=pad.address,
        action=ExceptionAction.CATCH,
    )
    frame = ExceptionFrame(function_start=0x401000, function_end=0x401050, landing_pads=[pad])

    expect(not (pad.action is not ExceptionAction.CATCH))
    expect(entry.landing_pad == _EXPECTED_ENTRY_LANDING_PAD_4198416)
    expect(frame.landing_pads[0].address == _EXPECTED_FRAME_LANDING_PADS_0_ADDRESS_4198416)
