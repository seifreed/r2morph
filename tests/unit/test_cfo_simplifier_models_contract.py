from r2morph.devirtualization.cfo_simplifier_models import (
    CFOPattern,
    CFOSimplificationResult,
    ControlFlowBlock,
    DispatcherInfo,
)


def test_cfo_simplifier_models_expose_expected_contract() -> None:
    block = ControlFlowBlock(address=0x1000, successors={0x2000})
    dispatcher = DispatcherInfo(dispatcher_address=0x3000, state_variable="state")
    result = CFOSimplificationResult(
        success=True,
        patterns_detected=[CFOPattern.DISPATCHER_FLATTENING],
        simplified_blocks={block.address: block},
        dispatcher_info=[dispatcher],
    )

    assert CFOPattern.SWITCH_CASE_OBFUSCATION.value == "switch_case_obfuscation"
    assert result.simplified_blocks[0x1000] is block
    assert result.dispatcher_info[0] is dispatcher
    assert block.successors == {0x2000}
