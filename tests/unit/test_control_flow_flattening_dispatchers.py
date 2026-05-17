from types import SimpleNamespace

from r2morph.mutations.cff_dispatcher import DispatcherGenerator


def test_control_flow_flattening_dispatcher_generators():
    blocks = [SimpleNamespace(address=0x1000), SimpleNamespace(address=0x2000)]

    x86_code = DispatcherGenerator().generate_x86(blocks, bits=64)
    assert x86_code
    assert any(".dispatcher_loop" in line for line in x86_code)

    arm_code = DispatcherGenerator().generate_arm(blocks, bits=64)
    assert arm_code
    assert any(".dispatcher_loop" in line for line in arm_code)
