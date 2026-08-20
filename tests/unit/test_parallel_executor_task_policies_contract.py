from r2morph.core.parallel_executor_task_policies import (
    build_task_priority,
    infer_task_dependencies,
    resolve_function_address,
    resolve_function_name,
)
from tests.utils.assertions import expect

_EXPECTED_ADDR_4660 = 0x1234
_EXPECTED_PRIORITY_3 = 3


def test_task_policies_resolve_address_name_and_priority() -> None:
    func = {"offset": 0x1234, "name": "demo"}

    addr = resolve_function_address(func)
    name = resolve_function_name(func, addr)
    priority = build_task_priority([1, 2, 3])

    expect(addr == _EXPECTED_ADDR_4660)
    expect(name == "demo")
    expect(priority == _EXPECTED_PRIORITY_3)


def test_task_policy_dependency_inference_uses_known_callers() -> None:
    call_graph = {0x1000: [0x2000], 0x2000: [0x3000], 0x3000: []}
    func_to_task = {0x1000: 1, 0x2000: 2}

    deps = infer_task_dependencies(0x3000, call_graph, func_to_task)

    expect(deps == [2])
