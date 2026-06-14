from r2morph.devirtualization.vm_handler_models import VMArchitecture, VMHandler, VMHandlerType


def test_vm_handler_models_expose_expected_contract() -> None:
    handler = VMHandler(handler_id=7, entry_address=0x401000, size=32, handler_type=VMHandlerType.DISPATCHER)
    architecture = VMArchitecture(dispatcher_address=0x402000, handlers={handler.handler_id: handler})

    assert VMHandlerType.UNKNOWN.value == "unknown"
    assert architecture.handlers[7] is handler
    assert architecture.dispatcher_address == 0x402000
