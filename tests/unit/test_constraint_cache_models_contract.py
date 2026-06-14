from r2morph.validation.constraint_cache_models import ConstraintCacheEntry


def test_constraint_cache_models_contract() -> None:
    entry = ConstraintCacheEntry(constraint_hash=1, result={"ok": True}, is_satisfiable=True, timestamp=1.0)
    assert entry.hit_count == 0
    assert entry.is_satisfiable is True
