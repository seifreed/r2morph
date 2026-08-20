from r2morph.devirtualization.vm_handler_models import VMArchitecture, VMHandler, VMHandlerType
from tests.utils.assertions import expect

_EXPECTED_ARCHITECTURE_DISPATCHER_ADDRESS_4202496 = 0x402000


def test_vm_handler_models_expose_expected_contract() -> None:
    handler = VMHandler(handler_id=7, entry_address=0x401000, size=32, handler_type=VMHandlerType.DISPATCHER)
    architecture = VMArchitecture(dispatcher_address=0x402000, handlers={handler.handler_id: handler})

    expect(VMHandlerType.UNKNOWN.value == "unknown")
    expect(not (architecture.handlers[7] is not handler))
    expect(architecture.dispatcher_address == _EXPECTED_ARCHITECTURE_DISPATCHER_ADDRESS_4202496)
