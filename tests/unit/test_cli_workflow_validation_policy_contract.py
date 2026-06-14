from r2morph.cli_workflow_validation_policy import build_validation_mode_policy
from r2morph.core.config import EngineConfig


def test_build_validation_mode_policy_bypasses_non_symbolic_modes() -> None:
    result = build_validation_mode_policy(
        requested_mode="runtime",
        mutations=["register"],
        config=EngineConfig(),
        seed=None,
        allow_limited_symbolic=False,
        limited_symbolic_policy="block",
    )

    assert result == {
        "effective_mode": "runtime",
        "policy": None,
        "reason": None,
        "limited_passes": [],
    }


def test_build_validation_mode_policy_degrades_limited_symbolic_passes() -> None:
    result = build_validation_mode_policy(
        requested_mode="symbolic",
        mutations=["register"],
        config=EngineConfig(),
        seed=None,
        allow_limited_symbolic=False,
        limited_symbolic_policy="degrade-runtime",
    )

    assert result == {
        "effective_mode": "runtime",
        "policy": "degrade-runtime",
        "reason": "limited-symbolic-support",
        "limited_passes": [{"mutation": "register", "pass_name": "RegisterSubstitution", "confidence": "limited"}],
    }


def test_build_validation_mode_policy_allows_explicit_override() -> None:
    result = build_validation_mode_policy(
        requested_mode="symbolic",
        mutations=["register"],
        config=EngineConfig(),
        seed=None,
        allow_limited_symbolic=True,
        limited_symbolic_policy="block",
    )

    assert result == {
        "effective_mode": "symbolic",
        "policy": "allow",
        "reason": "explicit-override",
        "limited_passes": [{"mutation": "register", "pass_name": "RegisterSubstitution", "confidence": "limited"}],
    }

