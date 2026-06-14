from r2morph.analysis.exception_models import (
    ExceptionAction,
    ExceptionFrame,
    ExceptionTableEntry,
    LandingPad,
)


def test_exception_models_contract() -> None:
    pad = LandingPad(address=0x401010, size=16, action=ExceptionAction.CATCH)
    entry = ExceptionTableEntry(
        start_address=0x401000,
        end_address=0x401020,
        landing_pad=pad.address,
        action=ExceptionAction.CATCH,
    )
    frame = ExceptionFrame(function_start=0x401000, function_end=0x401050, landing_pads=[pad])

    assert pad.action is ExceptionAction.CATCH
    assert entry.landing_pad == 0x401010
    assert frame.landing_pads[0].address == 0x401010
