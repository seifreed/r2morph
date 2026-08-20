from r2morph.mutations.hardened_cff import (
    HardenedControlFlowFlattening,
    create_hardened_cff_pass,
)
from r2morph.mutations.hardened_opaque import (
    HardenedOpaquePredicates,
    create_hardened_opaque_pass,
)
from tests.utils.assertions import expect


def test_hardened_pass_factories_create_expected_types():
    cff = create_hardened_cff_pass()
    opaque = create_hardened_opaque_pass()

    expect(isinstance(cff, HardenedControlFlowFlattening))
    expect(isinstance(opaque, HardenedOpaquePredicates))
