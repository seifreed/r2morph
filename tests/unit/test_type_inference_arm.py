from enum import Enum

from r2morph.analysis.type_inference_arm import infer_arm64_register_types


class _Primitive(Enum):
    FLOAT64 = "float64"
    UINT64 = "uint64"
    INT64 = "int64"


class _TypeFactory:
    def create_pointer_type(self) -> str:
        return "pointer"

    def create_primitive_type(self, primitive: _Primitive) -> str:
        return primitive.value


def test_infer_arm64_register_types_fmov_records_float64() -> None:
    register_types: dict[str, str] = {}

    infer_arm64_register_types(_TypeFactory(), "fmov d0, x0", register_types, _Primitive)

    assert register_types == {"d0": "float64"}
