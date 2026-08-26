"""Property coverage for malformed relocation instruction payloads."""

import json

from hypothesis import given
from hypothesis import strategies as st

from r2morph.relocations.manager import _parse_instruction_list
from tests.utils.assertions import expect


@given(
    st.lists(
        st.one_of(
            st.dictionaries(st.text(min_size=1, max_size=8), st.integers()),
            st.integers(),
            st.none(),
        ),
        max_size=20,
    )
)
def test_relocation_instruction_parser_filters_non_mapping_entries(entries: list[object]) -> None:
    parsed = _parse_instruction_list(json.dumps(entries))

    expect(all(isinstance(entry, dict) for entry in parsed))
