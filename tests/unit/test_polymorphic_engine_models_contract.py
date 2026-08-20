from r2morph.mutations.polymorphic_engine_models import (
    EngineRunResult,
    EngineState,
    MutationResult,
    StateTransition,
)
from tests.utils.assertions import expect


def test_polymorphic_engine_models_round_trip():
    transition = StateTransition(
        from_state=EngineState.INIT,
        to_state=EngineState.SUBSTITUTED,
        mutation_name="TestMutation",
    )
    result = MutationResult(
        name="TestMutation",
        state_before=EngineState.INIT,
        state_after=EngineState.SUBSTITUTED,
        success=True,
    )
    run_result = EngineRunResult(
        initial_state=EngineState.INIT,
        final_state=EngineState.FINAL,
        iterations=1,
        mutations_applied=[result],
    )

    expect(transition.to_state == EngineState.SUBSTITUTED)
    expect(run_result.mutations_applied[0].name == "TestMutation")
