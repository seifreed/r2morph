from r2morph.analysis.type_inference_interprocedural_params import (
    infer_all_function_param_types,
    infer_function_params,
    propagate_interprocedural_params,
)


class _PrimitiveType:
    INT64 = "int64"


class _TypeCategory:
    pass


class _TypeInfo:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _Factory:
    PrimitiveType = _PrimitiveType
    TypeCategory = _TypeCategory
    TypeInfo = _TypeInfo

    def __init__(self) -> None:
        self._address_types = {}

    def create_primitive_type(self, primitive):
        return ("primitive", primitive)

    def create_pointer_type(self):
        return ("pointer",)


class _Binary:
    def __init__(self) -> None:
        self._fns = [{"offset": 0x1000, "name": "f"}]

    def get_functions(self):
        return self._fns

    def get_function_disasm(self, addr):
        return [{"disasm": "mov rdi, rax"}] if addr == 0x1000 else []


def test_type_inference_interprocedural_params_contract() -> None:
    factory = _Factory()
    binary = _Binary()
    calling_conv = {"param_registers": ["rdi"], "return_register": "rax"}

    params = infer_function_params(factory, binary, 0x1000, [{"disasm": "mov rdi, rax"}], calling_conv)
    assert "param_0" in params

    all_params = infer_all_function_param_types(factory, binary, calling_conv)
    assert set(all_params) == {0x1000}

    function_types = {0x1000: {"param_0": ("primitive", "int64")}}
    propagate_interprocedural_params(factory, binary, {0x1000: [0x1000]}, function_types, calling_conv)
    assert factory._address_types
