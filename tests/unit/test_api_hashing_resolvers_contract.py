"""Contract tests for the API hashing resolver generators."""

from r2morph.mutations.api_hashing import (
    generate_resolve_function,
    generate_resolver_x64,
    generate_resolver_x86,
)
from r2morph.mutations.api_hashing_resolvers import (
    generate_resolve_function as leaf_generate_resolve_function,
)
from r2morph.mutations.api_hashing_resolvers import (
    generate_resolver_x64 as leaf_generate_resolver_x64,
)
from r2morph.mutations.api_hashing_resolvers import (
    generate_resolver_x86 as leaf_generate_resolver_x86,
)
from tests.utils.assertions import expect


def test_resolver_wrappers_delegate_to_leaf_module() -> None:
    expect(generate_resolver_x64(305419896) == leaf_generate_resolver_x64(305419896))
    expect(generate_resolver_x86(305419896) == leaf_generate_resolver_x86(305419896))
    expect(generate_resolve_function("x64") == leaf_generate_resolve_function("x64"))
    expect(generate_resolve_function("x86") == leaf_generate_resolve_function("x86"))


def test_generated_resolvers_encode_expected_symbols() -> None:
    x64 = generate_resolver_x64(0x12345678, "kernel32.dll")
    x86 = generate_resolver_x86(0x12345678, "kernel32.dll")
    generic = generate_resolve_function("x64")

    expect(not ("resolve_api_12345678" not in x64))
    expect(not ("resolve_api_12345678" not in x86))
    expect(not ("resolve_api_hash" not in generic))
