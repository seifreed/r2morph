from r2morph.devirtualization.cfo_simplifier_models import (
    CFOPattern,
    CFOSimplificationResult,
    ControlFlowBlock,
    DispatcherInfo,
)
from tests.utils.assertions import expect


def test_cfo_simplifier_models_expose_expected_contract() -> None:
    block = ControlFlowBlock(address=0x1000, successors={0x2000})
    dispatcher = DispatcherInfo(dispatcher_address=0x3000, state_variable="state")
    result = CFOSimplificationResult(
        success=True,
        patterns_detected=[CFOPattern.DISPATCHER_FLATTENING],
        simplified_blocks={block.address: block},
        dispatcher_info=[dispatcher],
    )

    expect(CFOPattern.SWITCH_CASE_OBFUSCATION.value == "switch_case_obfuscation")
    expect(not (result.simplified_blocks[0x1000] is not block))
    expect(not (result.dispatcher_info[0] is not dispatcher))
    expect(block.successors == {8192})
