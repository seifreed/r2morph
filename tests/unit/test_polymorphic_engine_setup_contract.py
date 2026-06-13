from r2morph.mutations.polymorphic_engine import PolymorphicEngine
from r2morph.mutations.polymorphic_engine_models import EngineState
from r2morph.mutations.polymorphic_engine_setup import setup_default_engine


def test_setup_default_engine_returns_final_state_and_registers_noop():
    engine = PolymorphicEngine()
    final_state = setup_default_engine(engine, enable_substitution=False, enable_dead_code=False, enable_reordering=False, enable_flattening=False, enable_virtualization=False, enable_string_obfuscation=False, enable_mobility=False, enable_outlining=False)

    assert final_state == EngineState.INIT
    assert "NoOp" in engine.mutations
    assert EngineState.INIT in engine.transitions
