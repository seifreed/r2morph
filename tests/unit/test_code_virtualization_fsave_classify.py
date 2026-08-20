"""
Unit tests for the ``fsave``/``frestore`` items: the region VM's flag transfer.

A stack-based interpreter brackets its dispatch with ``pushfq``/``popfq`` to preserve
the CPU flags across the computed jump. The region synthesizes an operation's readable
flags into its own flags slot rather than native RFLAGS, so a native flag save/restore
is lowered to ``fsave``/``frestore`` items that copy that slot to and from the virtual
operand stack - keeping the saved flags across the ``vm_dispatch`` re-entry. Lowering is
gated to the dispatch-region contract (the only shape where flag state crosses the jump),
like the ``ijmp`` computed jump it accompanies.

These exercise the pure classification and layout functions directly with hand-built
instruction dicts - no r2, no mocks.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_classification import _classify
from r2morph.mutations.code_virtualization_region_codegen_encode import _item_size
from r2morph.mutations.code_virtualization_region_models import _op_key
from tests.utils.assertions import expect


def test_classify_pushfq_yields_fsave_when_opted_in() -> None:
    """``pushfq`` lowers to an fsave (virtual RFLAGS saved onto the vstack)."""
    expect(_classify({"type": "upush", "opcode": "pushfq"}, allow_computed_jump=True) == ["fsave"])


def test_classify_popfq_yields_frestore_when_opted_in() -> None:
    """``popfq`` lowers to a frestore (virtual RFLAGS restored from the vstack)."""
    expect(_classify({"type": "upop", "opcode": "popfq"}, allow_computed_jump=True) == ["frestore"])


def test_classify_pushfq_rejected_by_default() -> None:
    """Without opt-in, a native flag save stays unsupported - the straight-line contract."""
    expect(not (_classify({"type": "upush", "opcode": "pushfq"}) is not None))


def test_classify_popfq_rejected_by_default() -> None:
    """Without opt-in, a native flag restore stays unsupported."""
    expect(not (_classify({"type": "upop", "opcode": "popfq"}) is not None))


def test_classify_register_push_is_not_flag_transfer() -> None:
    """A GP register push is unaffected by the flag-transfer path."""
    expect(_classify({"type": "upush", "opcode": "pushfq2"}, allow_computed_jump=True) != ["fsave"])


def test_fsave_op_key_is_its_own_handler_family() -> None:
    """The fsave item maps to a distinct handler key for opcode assignment."""
    expect(_op_key(("fsave",)) == "fsave")


def test_frestore_op_key_is_its_own_handler_family() -> None:
    """The frestore item maps to a distinct handler key for opcode assignment."""
    expect(_op_key(("frestore",)) == "frestore")


def test_flag_transfer_items_encode_as_a_single_opcode_byte() -> None:
    """fsave/frestore carry no operand - the vstack holds the value."""
    expect(_item_size(("fsave",)) == 1)
    expect(_item_size(("frestore",)) == 1)
