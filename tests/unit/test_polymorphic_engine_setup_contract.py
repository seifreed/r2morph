from r2morph.mutations.polymorphic_engine import PolymorphicEngine
from r2morph.mutations.polymorphic_engine_models import EngineState
from r2morph.mutations.polymorphic_engine_setup import EngineSetupConfig, setup_default_engine
from tests.utils.assertions import expect

_SEED = 20260914


def test_setup_default_engine_returns_final_state_and_registers_noop():
    engine = PolymorphicEngine()
    final_state = setup_default_engine(
        engine,
        EngineSetupConfig(
            enable_substitution=False,
            enable_pattern_substitution=False,
            enable_dead_code=False,
            enable_reordering=False,
            enable_flattening=False,
            enable_virtualization=False,
            enable_string_obfuscation=False,
            enable_mobility=False,
            enable_outlining=False,
        ),
    )

    expect(final_state == EngineState.INIT)
    expect(not ("NoOp" not in engine.mutations))
    expect(not (EngineState.INIT not in engine.transitions))


def test_setup_default_engine_propagates_explicit_seed_to_child_passes():
    engine = PolymorphicEngine(seed=_SEED)
    setup_default_engine(engine, EngineSetupConfig(seed=_SEED))

    expect(engine.mutations["InstructionSubstitution"].config.get("seed") == _SEED)
    expect(engine.mutations["NoOp"].config.get("seed") == _SEED)
