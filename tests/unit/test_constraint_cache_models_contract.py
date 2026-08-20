from r2morph.validation.constraint_cache_models import ConstraintCacheEntry
from tests.utils.assertions import expect


def test_constraint_cache_models_contract() -> None:
    entry = ConstraintCacheEntry(constraint_hash=1, result={"ok": True}, is_satisfiable=True, timestamp=1.0)
    expect(entry.hit_count == 0)
    expect(not (entry.is_satisfiable is not True))
