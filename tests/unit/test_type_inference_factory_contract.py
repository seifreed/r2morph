from r2morph.analysis.type_inference_factory import _extract_operand_size, _get_operand_size


class _PrimitiveType:
    INT8 = "int8"
    INT16 = "int16"
    INT32 = "int32"
    INT64 = "int64"
    UINT8 = "uint8"
    UINT16 = "uint16"
    UINT32 = "uint32"
    UINT64 = "uint64"
    FLOAT32 = "float32"
    FLOAT64 = "float64"
    BOOL = "bool"
    VOID = "void"


class _TypeCategory:
    PRIMITIVE = "primitive"
    POINTER = "pointer"
    ARRAY = "array"
    STRUCT = "struct"
    UNKNOWN = "unknown"


class _TypeInfo:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _Factory:
    PrimitiveType = _PrimitiveType
    TypeCategory = _TypeCategory
    TypeInfo = _TypeInfo

    def __init__(self) -> None:
        self._next = 0

    def _new_type_id(self) -> int:
        self._next += 1
        return self._next


def test_type_inference_factory_contract() -> None:
    factory = _Factory()

    assert _get_operand_size(factory, "rax") == 8
    assert _get_operand_size(factory, "eax") == 4
    assert _get_operand_size(factory, "ax") == 2
    assert _get_operand_size(factory, "al") == 1
    assert _extract_operand_size("mov qword ptr [rax], rbx") == 8
