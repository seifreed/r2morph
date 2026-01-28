from types import SimpleNamespace

from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def test_control_flow_flattening_dispatcher_generators():
    mutator = ControlFlowFlatteningPass()
    blocks = [SimpleNamespace(address=0x1000), SimpleNamespace(address=0x2000)]

    x86_code = mutator._generate_x86_dispatcher(blocks, bits=64)
    assert x86_code
    assert any(".dispatcher_loop" in line for line in x86_code)

    arm_code = mutator._generate_arm_dispatcher(blocks, bits=64)
    assert arm_code
    assert any(".dispatcher_loop" in line for line in arm_code)
