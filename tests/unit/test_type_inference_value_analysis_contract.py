from r2morph.analysis.type_inference_value_analysis import get_value_range, is_safe_to_mutate


class _TypeInfo:
    def __init__(self, size: int, integer: bool = False, pointer: bool = False) -> None:
        self.size = size
        self._integer = integer
        self._pointer = pointer

    def is_integer(self) -> bool:
        return self._integer

    def is_pointer(self) -> bool:
        return self._pointer


def test_type_inference_value_analysis_contract() -> None:
    assert get_value_range(_TypeInfo(4, integer=True)) == (0, 2**32 - 1)
    assert get_value_range(_TypeInfo(8, integer=False)) is None
    assert is_safe_to_mutate(_TypeInfo(8, pointer=True), "register_substitution")[0] is False
    assert is_safe_to_mutate(_TypeInfo(4, pointer=False), "instruction_expansion") == (True, "Safe to mutate")
