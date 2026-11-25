"""Property coverage for malformed relocation instruction payloads."""

import json

from hypothesis import given
from hypothesis import strategies as st

from r2morph.relocations.manager import RelocationManager, _parse_instruction_list
from tests._doubles.scripted_r2_binary import ScriptedR2Binary
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


@st.composite
def _overlapping_relocation_cases(draw: st.DrawFn) -> tuple[int, int, int]:
    first_size = draw(st.integers(min_value=3, max_value=256))
    second_offset = draw(st.integers(min_value=1, max_value=first_size - 2))
    query_offset = draw(st.integers(min_value=1, max_value=first_size - second_offset - 1))
    return first_size, second_offset, query_offset


@given(_overlapping_relocation_cases())
def test_latest_overlapping_relocation_maps_interior_bytes_consistently(
    case: tuple[int, int, int],
) -> None:
    first_size, second_offset, query_offset = case
    original_base = 0x1000
    first_destination = 0x4000
    second_destination = 0x8000
    manager = RelocationManager(ScriptedR2Binary({}))

    manager.add_relocation(original_base, first_destination, first_size)
    manager.add_relocation(original_base + second_offset, second_destination, query_offset + 1)

    expect(manager.get_new_address(original_base + second_offset + query_offset) == second_destination + query_offset)
