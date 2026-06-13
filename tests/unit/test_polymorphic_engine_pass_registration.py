"""Regression: PolymorphicEnginePass must register the mutations that its
default transitions reference.

``PolymorphicEnginePass._setup_engine`` adds state transitions whose
``mutation_name`` fields point at names like ``"InstructionSubstitution"``
and ``"NoOp"``, but the corresponding ``MutationPass`` instances were never
inserted into ``engine.mutations``. ``PolymorphicEngine.run`` looks each
transition's mutation up in that dict and breaks out of the loop on the
first miss with::

    if mutation is None:
        logger.warning(f"Mutation '{mutation_name}' not registered")
        break

so calling ``PolymorphicEnginePass().apply(binary)`` returned
``mutations_applied == 0`` immediately -- the pass was silently inert
regardless of the binary.

No-mocks regression (CLAUDE.md sec.4): real ``PolymorphicEnginePass``,
inspects the engine state ``_setup_engine`` built.
"""

from __future__ import annotations

from r2morph.mutations.polymorphic_engine import PolymorphicEnginePass


def test_every_default_transition_has_a_registered_mutation() -> None:
    """Every mutation_name referenced by a transition must resolve in
    engine.mutations -- otherwise run() bails out at the first iteration."""
    pass_obj = PolymorphicEnginePass()

    referenced_names: set[str] = set()
    for state_transitions in pass_obj.engine.transitions.values():
        for transition in state_transitions:
            referenced_names.add(transition.mutation_name)

    missing = referenced_names - set(pass_obj.engine.mutations.keys())
    assert not missing, (
        "PolymorphicEnginePass leaves transitions pointing at unregistered "
        f"mutations: {sorted(missing)!r}; engine.mutations.keys() = "
        f"{sorted(pass_obj.engine.mutations.keys())!r}"
    )


def test_disabled_mutation_is_not_registered_either() -> None:
    """Disabling a mutation must also keep it out of engine.mutations so
    the auto-registration stays in lock-step with the auto-transitions:
    every registered transition has a registered mutation, and only the
    enabled ones get added in either place."""
    pass_obj = PolymorphicEnginePass(
        {
            "enable_substitution": True,
            "enable_dead_code": False,
            "enable_reordering": False,
            "enable_flattening": False,
            "enable_string_obfuscation": False,
            "enable_virtualization": False,
            "enable_mobility": False,
            "enable_outlining": False,
        }
    )

    # Mutation names registered must be exactly the enabled set (+NoOp).
    expected = {"InstructionSubstitution", "NoOp"}
    assert set(pass_obj.engine.mutations.keys()) == expected, (
        f"expected mutation registration = {expected!r}; got " f"{set(pass_obj.engine.mutations.keys())!r}"
    )

    # And no transition can reference a name outside the registered set.
    referenced: set[str] = set()
    for state_transitions in pass_obj.engine.transitions.values():
        for transition in state_transitions:
            referenced.add(transition.mutation_name)
    assert referenced.issubset(expected), (
        f"transitions reference names outside the registered set: " f"{referenced - expected!r}"
    )


def test_apply_attempts_the_first_transition_with_default_config() -> None:
    """End-to-end: with default config and a minimal Binary stand-in,
    ``apply`` must actually try to invoke the first transition's
    mutation. Pre-fix every iteration broke BEFORE invocation with
    ``"Mutation 'InstructionSubstitution' not registered"`` -- the
    counters stayed at zero. Post-fix the mutation is dispatched
    (``mutations_applied >= 1``); whether the dispatched mutation
    completes against this minimal stand-in is out of scope -- the
    contract this test pins is "the dispatcher reaches the mutation
    object", not "the mutation tolerates an empty binary"."""

    class _BinaryStandIn:
        """Bare-minimum Binary protocol surface so the engine can call
        ``apply`` on the registered mutation. We don't care whether the
        mutation succeeds against this stand-in -- only that the engine
        actually dispatches to it. This is a fake (a hand-written
        implementation of the binary protocol surface the engine
        consumer touches), not a mock object in the unittest.mock sense."""

        def is_analyzed(self) -> bool:
            return True

        def analyze(self) -> _BinaryStandIn:
            return self

        def get_functions(self) -> list[dict[str, object]]:
            return []

        def get_arch_info(self) -> dict[str, object]:
            return {"arch": "x86_64", "bits": 64}

    pass_obj = PolymorphicEnginePass({"max_iterations": 20})
    result = pass_obj.apply(_BinaryStandIn())

    assert result["iterations"] > 0, (
        "PolymorphicEnginePass.apply() did not advance past the first "
        f"transition -- mutations are likely unregistered; result={result!r}"
    )
    assert result["mutations_applied"] > 0, (
        "PolymorphicEnginePass.apply() never reached the mutation " f"dispatcher; result={result!r}"
    )
