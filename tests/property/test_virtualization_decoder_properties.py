"""Property coverage for malformed virtualization decoder input."""

from hypothesis import given
from hypothesis import strategies as st

from r2morph.mutations.code_virtualization import _decode_run_item
from r2morph.mutations.code_virtualization_engine_models import (
    VirtualizedFpArithMemOp,
    VirtualizedFpArithOp,
    VirtualizedFpConvertOp,
    VirtualizedFpMemOp,
    VirtualizedFpPackedMemOp,
    VirtualizedFpPackedOp,
    VirtualizedMemOp,
    VirtualizedOp,
)
from tests.utils.assertions import expect

_VIRTUALIZED_ITEM_TYPES = (
    VirtualizedOp,
    VirtualizedMemOp,
    VirtualizedFpMemOp,
    VirtualizedFpArithOp,
    VirtualizedFpConvertOp,
    VirtualizedFpArithMemOp,
    VirtualizedFpPackedOp,
    VirtualizedFpPackedMemOp,
)


@given(
    text=st.text(max_size=96),
    address=st.integers(min_value=0, max_value=0xFFFFFFFF),
    size=st.integers(min_value=0, max_value=32),
)
def test_virtualization_decoder_accepts_arbitrary_text_with_known_result_type(
    text: str,
    address: int,
    size: int,
) -> None:
    decoded = _decode_run_item(text, address, size)

    expect(decoded is None or isinstance(decoded, _VIRTUALIZED_ITEM_TYPES))
