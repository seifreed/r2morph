"""
Tests for semantic_validation module (post-mutation validation).
"""

from r2morph.mutations.semantic_validation import (
    SemanticValidator,
    ValidationIssue,
    ValidationResult,
    ValidationSeverity,
    create_validator,
)
from tests.utils.assertions import expect

_EXPECTED_ISSUE_ADDRESS_4096 = 0x1000
_EXPECTED_LEN_RESULT_ERRORS_2 = 2
_EXPECTED_VALIDATOR_GET_ADDRESS_ADDRESS_4096_4096 = 4096
_EXPECTED_VALIDATOR_GET_ADDRESS_ADDR_0X1000_4096 = 0x1000
_EXPECTED_VALIDATOR_GET_ADDRESS_ADDR_0X1000_4096_2 = 0x1000


class TestValidationIssue:
    def test_issue_creation(self):
        issue = ValidationIssue(
            code="TEST_CODE",
            severity=ValidationSeverity.ERROR,
            message="Test message",
            address=0x1000,
            details={"key": "value"},
        )
        expect(issue.code == "TEST_CODE")
        expect(issue.severity == ValidationSeverity.ERROR)
        expect(issue.message == "Test message")
        expect(issue.address == _EXPECTED_ISSUE_ADDRESS_4096)
        expect(issue.details == {"key": "value"})


class TestValidationResult:
    def test_result_creation(self):
        result = ValidationResult(valid=True)
        expect(not (result.valid is not True))
        expect(result.issues == [])

    def test_add_error(self):
        result = ValidationResult(valid=True)
        result.add_error("ERR001", "Error message", 0x1000, key="value")
        expect(not (result.valid is not False))
        expect(len(result.errors) == 1)
        expect(result.errors[0].code == "ERR001")

    def test_add_warning(self):
        result = ValidationResult(valid=True)
        result.add_warning("WARN001", "Warning message", 0x1000)
        expect(not (result.valid is not True))
        expect(len(result.warnings) == 1)
        expect(result.warnings[0].code == "WARN001")

    def test_errors_property(self):
        result = ValidationResult(valid=True)
        result.add_error("ERR001", "Error 1", 0)
        result.add_warning("WARN001", "Warning 1", 0)
        result.add_error("ERR002", "Error 2", 0)
        expect(len(result.errors) == _EXPECTED_LEN_RESULT_ERRORS_2)
        expect(len(result.warnings) == 1)


class TestSemanticValidator:
    def test_validator_creation(self):
        validator = SemanticValidator()
        expect(validator.arch == "x86_64")

    def test_validator_arch(self):
        validator = SemanticValidator(arch="arm64")
        expect(validator.arch == "arm64")

    def test_validate_empty_instructions(self):
        validator = SemanticValidator()
        result = validator.validate_basic_block([])
        expect(not (result.valid is not True))

    def test_validate_simple_mov(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "mov", "operand_1": "rax", "operand_2": "rbx"},
        ]
        result = validator.validate_basic_block(instructions)
        expect(not (result.valid is not True))

    def test_validate_push_pop_balanced(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
            {"addr": 0x1002, "mnemonic": "pop", "operand_1": "rbx"},
        ]
        result = validator.validate_basic_block(instructions)
        expect(not (result.valid is not True))
        expect(result.metadata.get("stack_depth") == 0)

    def test_validate_push_without_pop(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
        ]
        result = validator.validate_basic_block(instructions)
        expect(not (result.valid is not False))
        expect(any(i.code == "STACK_UNBALANCED" for i in result.errors))

    def test_validate_pop_without_push(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "pop", "operand_1": "rbx"},
        ]
        result = validator.validate_basic_block(instructions)
        expect(not (result.valid is not False))
        expect(any(i.code == "STACK_UNDERFLOW" for i in result.errors))

    def test_validate_preserved_register_modification(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
            {"addr": 0x1002, "mnemonic": "add", "operand_1": "rbx", "operand_2": "1"},
            {"addr": 0x1004, "mnemonic": "pop", "operand_1": "rbx"},
        ]
        result = validator.validate_basic_block(instructions, preserve_registers=True)
        expect(not ("rbx" not in result.metadata.get("preserved_touched", [])))

    def test_validate_function_empty(self):
        validator = SemanticValidator()
        result = validator.validate_function([])
        expect(not (result.valid is not True))

    def test_validate_function_register_not_restored(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
            {"addr": 0x1002, "mnemonic": "ret"},
        ]
        result = validator.validate_function(instructions)
        expect(not (result.valid is not False))
        expect(any(i.code == "REGISTER_NOT_RESTORED" for i in result.errors))

    def test_validate_function_proper_save_restore(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
            {"addr": 0x1002, "mnemonic": "push", "operand_1": "r12"},
            {"addr": 0x1004, "mnemonic": "mov", "operand_1": "rax", "operand_2": "0"},
            {"addr": 0x1006, "mnemonic": "pop", "operand_1": "r12"},
            {"addr": 0x1008, "mnemonic": "pop", "operand_1": "rbx"},
            {"addr": 0x100A, "mnemonic": "ret"},
        ]
        result = validator.validate_function(instructions)
        expect(not ("rbx" not in result.metadata.get("saved_registers", [])))
        expect(not ("r12" not in result.metadata.get("saved_registers", [])))
        expect(not ("rbx" not in result.metadata.get("restored_registers", [])))
        expect(not ("r12" not in result.metadata.get("restored_registers", [])))


class TestValidateMutation:
    def test_validate_mutation_valid(self):
        validator = SemanticValidator()
        original = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
            {"addr": 0x1002, "mnemonic": "pop", "operand_1": "rbx"},
        ]
        mutated = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
            {"addr": 0x1002, "mnemonic": "pop", "operand_1": "rbx"},
        ]
        result = validator.validate_mutation(original, mutated)
        expect(not (result.valid is not True))

    def test_validate_mutation_stack_imbalance(self):
        validator = SemanticValidator()
        original = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
            {"addr": 0x1002, "mnemonic": "pop", "operand_1": "rbx"},
        ]
        mutated = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
            {"addr": 0x1002, "mnemonic": "push", "operand_1": "r12"},
        ]
        result = validator.validate_mutation(original, mutated)
        expect(not (result.valid is not False))
        expect(any(i.code == "STACK_DEPTH_MISMATCH" for i in result.errors))

    def test_validate_mutation_unsafe_opcode(self):
        validator = SemanticValidator()
        original = [{"addr": 0x1000, "mnemonic": "nop"}]
        mutated = [{"addr": 0x1000, "mnemonic": "syscall"}]
        result = validator.validate_mutation(original, mutated)
        expect(any(i.code == "UNSAFE_OPCODE" for i in result.warnings))


class TestValidateJunkCode:
    def test_validate_empty_junk(self):
        validator = SemanticValidator()
        result = validator.validate_junk_code([])
        expect(not (result.valid is not True))

    def test_validate_safe_junk(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "mov", "operand_1": "rax", "operand_2": "rbx"},
            {"addr": 0x1002, "mnemonic": "add", "operand_1": "rax", "operand_2": "1"},
            {"addr": 0x1004, "mnemonic": "nop"},
        ]
        result = validator.validate_junk_code(instructions)
        expect(not (result.valid is not True))

    def test_validate_unsafe_junk(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "syscall"},
        ]
        result = validator.validate_junk_code(instructions)
        expect(not (result.valid is not False))
        expect(any(i.code == "JUNK_UNSAFE_OPCODE" for i in result.errors))

    def test_validate_junk_memory_access(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "mov", "operand_1": "rax", "operand_2": "[rbx]"},
        ]
        result = validator.validate_junk_code(instructions)
        expect(any(i.code == "JUNK_MEMORY_ACCESS" for i in result.warnings))


class TestValidatorPrivateMethods:
    def test_get_mnemonic(self):
        validator = SemanticValidator()
        expect(validator._get_mnemonic({"mnemonic": "MOV"}) == "mov")
        expect(validator._get_mnemonic({"type": "CALL"}) == "call")

    def test_get_address(self):
        validator = SemanticValidator()
        expect(validator._get_address({"addr": 4096}) == _EXPECTED_VALIDATOR_GET_ADDRESS_ADDR_0X1000_4096)
        expect(validator._get_address({"address": 4096}) == _EXPECTED_VALIDATOR_GET_ADDRESS_ADDRESS_4096_4096)
        expect(validator._get_address({"addr": "0x1000"}) == _EXPECTED_VALIDATOR_GET_ADDRESS_ADDR_0X1000_4096_2)

    def test_get_operand(self):
        validator = SemanticValidator()
        ins = {"operand_1": "rax", "operand_2": "rbx"}
        expect(validator._get_operand(ins, 0) == "rax")
        expect(validator._get_operand(ins, 1) == "rbx")

        ins2 = {"operands": ["rcx", "rdx"]}
        expect(validator._get_operand(ins2, 0) == "rcx")
        expect(validator._get_operand(ins2, 1) == "rdx")


class TestCreateValidator:
    def test_create_validator_default(self):
        validator = create_validator()
        expect(validator.arch == "x86_64")

    def test_create_validator_custom_arch(self):
        validator = create_validator(arch="arm64")
        expect(validator.arch == "arm64")


class TestEdgeCases:
    def test_nested_push_pop(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
            {"addr": 0x1002, "mnemonic": "push", "operand_1": "r12"},
            {"addr": 0x1004, "mnemonic": "pop", "operand_1": "r12"},
            {"addr": 0x1006, "mnemonic": "pop", "operand_1": "rbx"},
        ]
        result = validator.validate_basic_block(instructions)
        expect(not (result.valid is not True))

    def test_unbalanced_nested_push_pop(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
            {"addr": 0x1002, "mnemonic": "push", "operand_1": "r12"},
            {"addr": 0x1004, "mnemonic": "pop", "operand_1": "rbx"},
        ]
        result = validator.validate_basic_block(instructions)
        expect(not (result.valid is not False))

    def test_control_flow_preservation(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "jmp", "jump": 0x2000},
        ]
        result = validator.validate_basic_block(instructions, check_control_flow=True)
        expect(any(i.code == "JUMP_EXTERNAL" for i in result.warnings))

    def test_abi_windows(self):
        validator = SemanticValidator()
        instructions = [
            {"addr": 0x1000, "mnemonic": "push", "operand_1": "rbx"},
            {"addr": 0x1002, "mnemonic": "ret"},
        ]
        result = validator.validate_function(instructions, abi="windows")
        expect(not (result.valid is not False))
