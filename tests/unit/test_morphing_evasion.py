"""
Tests for new morphing/evasion modules.

Tests for:
- API Hashing (api_hashing.py)
- Stack Strings (stack_strings.py)
- Code Virtualization (code_virtualization.py)
- Function Outlining (function_outlining.py)
- Code Mobility (code_mobility.py)
- Polymorphic Engine (polymorphic_engine.py)
- Self-Modifying Code (self_modifying_code.py)
- Anti-Disassembly (anti_disassembly.py)
"""

import pytest
from r2morph.mutations.api_hashing import (
    hash_ror13,
    hash_ror7,
    hash_djb2,
    hash_fnv1a,
    hash_crc32,
    HASH_ALGORITHMS,
    COMMON_WINDOWS_APIS,
    COMMON_LINUX_APIS,
    APIHashingPass,
    generate_resolver_x64,
    generate_resolver_x86,
)
from r2morph.mutations.stack_strings import (
    StackStringsPass,
    EncodingScheme,
    generate_stack_string_x64,
    generate_stack_string_x86,
    find_printable_strings,
    xor_bytes,
    xor_rolling,
    add_shift_encode,
    aes_encrypt_string,
    aes_decrypt_block,
)
from r2morph.mutations.code_virtualization import (
    VMOpcode,
    VMHandler,
    VMInstruction,
    VMContext,
    REG_MAP_X64,
    REG_MAP_X86,
    CodeVirtualizationPass,
    translate_instruction_to_vm,
    generate_vm_dispatcher_x64,
    generate_vm_handler_x64,
    VMProfile,
    MULTI_VM_PROFILES,
    MultiVMVirtualizationPass,
)
from r2morph.mutations.function_outlining import (
    OutlinedChunk,
    OutlinedFunction,
    FunctionOutliningPass,
    calculate_chunk_layout,
    generate_interleaved_layout,
)
from r2morph.mutations.code_mobility import (
    MobileBlock,
    CodeMobilityPass,
    calculate_section_offsets,
    estimate_size_with_jumps,
)
from r2morph.mutations.polymorphic_engine import (
    EngineState,
    StateTransition,
    MutationResult,
    EngineRunResult,
    PolymorphicEngine,
    PolymorphicEnginePass,
    NoOp,
)
from r2morph.mutations.self_modifying_code import (
    EncryptionScheme,
    EncryptedSection,
    DecryptStub,
    xor_encrypt,
    xor_rolling_encrypt,
    add_sub_encrypt,
    rol_encrypt,
    rc4_crypt,
    generate_polymorphic_stub_x64,
    SelfModifyingCodePass,
    create_packed_binary,
)
from r2morph.mutations.anti_disassembly import (
    AntiDisasmType,
    AntiDisasmSnippet,
    OVERLAPPING_X64,
    JUMP_MIDDLE_X64,
    FALSE_BRANCH_X64,
    SEH_BASED_X64,
    POLYGLOT_X64_86,
    TRAMPOLINE_X64,
    ALL_ANTI_DISASM_X64,
    generate_false_disasm_sequence,
    generate_opaque_predicate_x64,
    generate_sled_obfuscation,
    AntiDisassemblyPass,
)
from r2morph.mutations.stack_strings import (
    StackStringsPass,
    EncodingScheme,
    generate_stack_string_x64,
    generate_stack_string_x86,
    find_printable_strings,
    xor_bytes,
    xor_rolling,
    add_shift_encode,
)
from r2morph.mutations.code_virtualization import (
    VMOpcode,
    VMHandler,
    VMInstruction,
    VMContext,
    REG_MAP_X64,
    REG_MAP_X86,
    CodeVirtualizationPass,
    translate_instruction_to_vm,
    generate_vm_dispatcher_x64,
    generate_vm_handler_x64,
)
from r2morph.mutations.function_outlining import (
    OutlinedChunk,
    OutlinedFunction,
    FunctionOutliningPass,
    calculate_chunk_layout,
    generate_interleaved_layout,
)
from r2morph.mutations.code_mobility import (
    MobileBlock,
    MobilityPlan,
    CodeMobilityPass,
    calculate_section_offsets,
    estimate_size_with_jumps,
)
from r2morph.mutations.polymorphic_engine import (
    EngineState,
    StateTransition,
    MutationResult,
    EngineRunResult,
    PolymorphicEngine,
    PolymorphicEnginePass,
    NoOp,
)


class TestAPIHashing:
    """Tests for API hashing functions."""

    def test_hash_ror13_known_values(self):
        result = hash_ror13("CreateFileA")
        assert isinstance(result, int)
        assert result > 0

    def test_hash_ror13_case_insensitive(self):
        assert hash_ror13("CreateFileA") == hash_ror13("createfilea")

    def test_hash_ror7_different_from_ror13(self):
        assert hash_ror7("test") != hash_ror13("test")

    def test_hash_djb2_known(self):
        result = hash_djb2("test")
        assert isinstance(result, int)
        assert result > 0

    def test_hash_fnv1a_known(self):
        result = hash_fnv1a("test")
        assert isinstance(result, int)
        assert result > 0

    def test_hash_crc32_known(self):
        result = hash_crc32("test")
        assert isinstance(result, int)
        assert result >= 0

    def test_hash_algorithms_dict(self):
        assert "ror13" in HASH_ALGORITHMS
        assert "ror7" in HASH_ALGORITHMS
        assert "djb2" in HASH_ALGORITHMS
        assert "fnv1a" in HASH_ALGORITHMS
        assert "crc32" in HASH_ALGORITHMS

    def test_common_apis_lists(self):
        assert "CreateFileA" in COMMON_WINDOWS_APIS
        assert "VirtualAlloc" in COMMON_WINDOWS_APIS
        assert "open" in COMMON_LINUX_APIS
        assert "mmap" in COMMON_LINUX_APIS

    def test_generate_resolver_x64(self):
        asm = generate_resolver_x64(0x12345678)
        assert "resolve_api" in asm
        assert "gs:[0x60]" in asm
        assert "PEB" in asm or "ldr" in asm.lower()

    def test_generate_resolver_x86(self):
        asm = generate_resolver_x86(0x12345678)
        assert "resolve_api" in asm
        assert "fs:[0x30]" in asm

    def test_api_hashing_pass_init(self):
        config = {"hash_algorithm": "ror13", "arch": "x64"}
        p = APIHashingPass(config)
        assert p.hash_algorithm == "ror13"
        assert p.arch == "x64"

    def test_api_hashing_pass_get_hashes(self):
        p = APIHashingPass()
        hashes = p.get_api_hashes()
        assert isinstance(hashes, dict)
        assert len(hashes) > 0
        assert all(isinstance(v, int) for v in hashes.values())


class TestStackStrings:
    """Tests for stack string functions."""

    def test_encoding_scheme_values(self):
        assert EncodingScheme.PLAIN == "plain"
        assert EncodingScheme.XOR_SINGLE == "xor_single"
        assert EncodingScheme.XOR_ROLLING == "xor_rolling"
        assert EncodingScheme.ADD_SHIFT == "add_shift"

    def test_xor_bytes(self):
        data = b"Hello"
        result = xor_bytes(data, 0x55)
        assert len(result) == len(data)
        assert result != data
        recovered = xor_bytes(result, 0x55)
        assert recovered == data

    def test_xor_rolling(self):
        data = b"Hello"
        result, final_key = xor_rolling(data, 0x42)
        assert len(result) == len(data)
        assert result != data

    def test_add_shift_encode(self):
        data = b"Hello"
        result = add_shift_encode(data, 5)
        assert len(result) == len(data)
        assert result != data

    def test_find_printable_strings(self):
        data = b"Hello\x00World\x00Test\x00"
        strings = find_printable_strings(data, min_length=4)
        assert len(strings) >= 1
        assert len(strings[0]) == 2
        assert strings[0][1] == b"Hello" or strings[0][1].startswith(b"Hello")

    def test_generate_stack_string_x64_plain(self):
        string_data = b"Hello"
        asm, junk = generate_stack_string_x64(string_data, EncodingScheme.PLAIN)
        assert "sub rsp" in asm
        assert "mov byte" in asm

    def test_generate_stack_string_x64_xor(self):
        string_data = b"Hello"
        asm, junk = generate_stack_string_x64(string_data, EncodingScheme.XOR_SINGLE, xor_key=0x55)
        assert "sub rsp" in asm
        assert "xor" in asm

    def test_generate_stack_string_x86_plain(self):
        string_data = b"Test"
        asm, junk = generate_stack_string_x86(string_data, EncodingScheme.PLAIN)
        assert "sub esp" in asm
        assert "mov byte" in asm

    def test_generate_stack_string_with_junk(self):
        string_data = b"Test"
        asm, junk = generate_stack_string_x64(
            string_data, EncodingScheme.PLAIN, interleave_junk=True, junk_probability=1.0
        )
        assert len(junk) > 0

    def test_stack_strings_pass_init(self):
        config = {"probability": 0.5, "encoding": "xor_single"}
        p = StackStringsPass(config)
        assert p.probability == 0.5
        assert p.encoding == "xor_single"

    def test_stack_strings_pass_preview(self):
        p = StackStringsPass()
        asm = p.preview_string("Hello World")
        assert "sub rsp" in asm


class TestCodeVirtualization:
    """Tests for code virtualization functions."""

    def test_vm_opcode_values(self):
        assert VMOpcode.NOP == 0x00
        assert VMOpcode.MOV_REG_REG == 0x01
        assert VMOpcode.PUSH_REG == 0x10
        assert VMOpcode.ADD_REG_IMM == 0x21

    def test_vm_instruction_to_bytecode(self):
        insn = VMInstruction(VMOpcode.NOP, [], "nop")
        bytecode = insn.to_bytecode()
        assert bytecode == bytes([VMOpcode.NOP])

    def test_vm_instruction_with_operand(self):
        insn = VMInstruction(VMOpcode.MOV_REG_IMM, [0, 42], "mov vreg0, 42")
        bytecode = insn.to_bytecode()
        assert len(bytecode) > 1
        assert bytecode[0] == VMOpcode.MOV_REG_IMM

    def test_vm_instruction_with_string_operand(self):
        insn = VMInstruction(VMOpcode.JMP, ["label_1"], "jmp label_1")
        bytecode = insn.to_bytecode()
        assert bytecode[0] == VMOpcode.JMP

    def test_vm_context_initialization(self):
        ctx = VMContext()
        assert ctx.pc == 0
        assert ctx.running is True
        assert len(ctx.stack) == 0

    def test_reg_map_x64(self):
        assert REG_MAP_X64["rax"] == 0
        assert REG_MAP_X64["rcx"] == 1
        assert REG_MAP_X64["r15"] == 15

    def test_reg_map_x86(self):
        assert REG_MAP_X86["eax"] == 0
        assert REG_MAP_X86["ebx"] == 3

    def test_translate_instruction_to_vm_mov(self):
        insn = {"mnemonic": "mov", "op1": "eax", "op2": "42"}
        vm_insn = translate_instruction_to_vm(insn, "x64")
        assert vm_insn is not None
        assert vm_insn.opcode == VMOpcode.MOV_REG_IMM

    def test_translate_instruction_to_vm_add(self):
        insn = {"mnemonic": "add", "op1": "eax", "op2": "5"}
        vm_insn = translate_instruction_to_vm(insn, "x64")
        assert vm_insn is not None
        assert vm_insn.opcode == VMOpcode.ADD_REG_IMM

    def test_translate_instruction_to_vm_push(self):
        insn = {"mnemonic": "push", "op1": "42"}
        vm_insn = translate_instruction_to_vm(insn, "x64")
        assert vm_insn is not None
        assert vm_insn.opcode == VMOpcode.PUSH_IMM

    def test_translate_instruction_to_vm_unsupported(self):
        insn = {"mnemonic": "syscall"}
        vm_insn = translate_instruction_to_vm(insn, "x64")
        assert vm_insn is None

    def test_generate_vm_dispatcher_x64(self):
        asm = generate_vm_dispatcher_x64()
        assert "vm_execute" in asm
        assert "vm_handlers" in asm

    def test_generate_vm_handler_x64_nop(self):
        asm = generate_vm_handler_x64(VMOpcode.NOP)
        assert "vm_handler_00" in asm

    def test_generate_vm_handler_x64_mov(self):
        asm = generate_vm_handler_x64(VMOpcode.MOV_REG_IMM)
        assert "vm_handler_02" in asm

    def test_code_virtualization_pass_init(self):
        config = {"probability": 0.5}
        p = CodeVirtualizationPass(config)
        assert p.probability == 0.5


class TestFunctionOutlining:
    """Tests for function outlining functions."""

    def test_outlined_chunk_creation(self):
        chunk = OutlinedChunk(
            chunk_id=0x100,
            original_address=0x401000,
            instructions=[],
            section=".outlined",
        )
        assert chunk.chunk_id == 0x100
        assert chunk.original_address == 0x401000

    def test_outlined_chunk_to_asm(self):
        chunk = OutlinedChunk(
            chunk_id=0x100,
            original_address=0x401000,
            instructions=[{"disasm": "mov eax, 1"}, {"disasm": "ret"}],
        )
        asm = chunk.to_asm()
        assert "chunk_0100:" in asm
        assert "mov eax, 1" in asm

    def test_outlined_function_creation(self):
        func = OutlinedFunction(
            original_address=0x401000,
            original_name="test_func",
        )
        assert func.original_address == 0x401000
        assert len(func.chunks) == 0

    def test_outlined_function_add_chunk(self):
        func = OutlinedFunction(original_address=0x401000, original_name="test_func")
        chunk = OutlinedChunk(chunk_id=0x100, original_address=0x401000, instructions=[])
        func.add_chunk(chunk)
        assert len(func.chunks) == 1

    def test_outlined_function_get_chunk_order(self):
        func = OutlinedFunction(original_address=0x401000, original_name="test_func")
        for i in range(3):
            chunk = OutlinedChunk(chunk_id=i, original_address=0x401000 + i * 0x100, instructions=[])
            func.chunks.append(chunk)
        order = func.get_chunk_order()
        assert len(order) >= 0

    def test_function_outlining_pass_init(self):
        config = {"probability": 0.5, "max_functions": 10}
        p = FunctionOutliningPass(config)
        assert p.probability == 0.5
        assert p.max_functions == 10

    def test_calculate_chunk_layout(self):
        chunks = [OutlinedChunk(chunk_id=i, original_address=i * 0x100, instructions=[]) for i in range(3)]
        layout = calculate_chunk_layout(chunks)
        assert len(layout) == 3

    def test_generate_interleaved_layout(self):
        func1 = OutlinedFunction(original_address=0x1000, original_name="f1")
        func2 = OutlinedFunction(original_address=0x2000, original_name="f2")
        for i in range(2):
            func1.chunks.append(OutlinedChunk(chunk_id=i, original_address=0x1000 + i * 0x100, instructions=[]))
            func2.chunks.append(OutlinedChunk(chunk_id=100 + i, original_address=0x2000 + i * 0x100, instructions=[]))
        result = generate_interleaved_layout([func1, func2], seed=42)
        assert len(result) == 4


class TestCodeMobility:
    """Tests for code mobility functions."""

    def test_mobile_block_creation(self):
        block = MobileBlock(
            block_id=0,
            original_address=0x401000,
            original_section=".text",
            size=32,
            target_section=".mobile_0",
        )
        assert block.block_id == 0
        assert block.original_address == 0x401000

    def test_mobile_block_get_jump_size(self):
        block = MobileBlock(block_id=0, original_address=0x1000, original_section=".text", size=100)
        assert block.get_jump_size() == 5

    def test_mobility_plan_creation(self):
        plan = MobilityPlan()
        assert len(plan.blocks) == 0

    def test_mobility_plan_add_block(self):
        plan = MobilityPlan()
        block = MobileBlock(
            block_id=0, original_address=0x1000, original_section=".text", size=32, target_section=".mobile_0"
        )
        plan.add_block(block)
        assert len(plan.blocks) == 1
        assert ".mobile_0" in plan.section_layout

    def test_code_mobility_pass_init(self):
        config = {"probability": 0.3, "max_blocks": 50}
        p = CodeMobilityPass(config)
        assert p.probability == 0.3
        assert p.max_blocks == 50

    def test_calculate_section_offsets(self):
        sections = [".mobile_0", ".mobile_1", ".mobile_2"]
        offsets = calculate_section_offsets(sections)
        assert len(offsets) == 3
        assert all(addr > 0 for addr in offsets.values())

    def test_estimate_size_with_jumps(self):
        blocks = [
            MobileBlock(block_id=i, original_address=i * 0x100, original_section=".text", size=32) for i in range(3)
        ]
        size = estimate_size_with_jumps(blocks)
        assert size > sum(b.size for b in blocks)


class TestPolymorphicEngine:
    """Tests for polymorphic engine functions."""

    def test_engine_state_values(self):
        assert hasattr(EngineState, "INIT")
        assert hasattr(EngineState, "FINAL")
        assert hasattr(EngineState, "SUBSTITUTED")

    def test_state_transition_creation(self):
        trans = StateTransition(
            from_state=EngineState.INIT,
            to_state=EngineState.SUBSTITUTED,
            mutation_name="TestMutation",
        )
        assert trans.from_state == EngineState.INIT
        assert trans.to_state == EngineState.SUBSTITUTED

    def test_mutation_result_creation(self):
        result = MutationResult(
            name="Test",
            state_before=EngineState.INIT,
            state_after=EngineState.SUBSTITUTED,
            success=True,
        )
        assert result.success is True
        assert result.name == "Test"

    def test_engine_run_result_creation(self):
        result = EngineRunResult(
            initial_state=EngineState.INIT,
            final_state=EngineState.FINAL,
            iterations=5,
        )
        assert result.iterations == 5
        assert result.converged is False

    def test_polymorphic_engine_init(self):
        engine = PolymorphicEngine(seed=42)
        assert engine.seed == 42
        assert engine.current_state == EngineState.INIT

    def test_polymorphic_engine_add_mutation(self):
        engine = PolymorphicEngine()
        mutation = NoOp()
        engine.add_mutation("test", mutation)
        assert "test" in engine.mutations

    def test_polymorphic_engine_add_transition(self):
        engine = PolymorphicEngine()
        engine.add_transition(EngineState.INIT, EngineState.SUBSTITUTED, "TestMutation")
        assert EngineState.INIT in engine.transitions
        assert len(engine.transitions[EngineState.INIT]) == 1

    def test_polymorphic_engine_get_available_transitions(self):
        engine = PolymorphicEngine()
        engine.add_transition(EngineState.INIT, EngineState.SUBSTITUTED, "Test")
        available = engine.get_available_transitions(EngineState.INIT)
        assert len(available) == 1

    def test_polymorphic_engine_get_state_graph(self):
        engine = PolymorphicEngine()
        engine.add_transition(EngineState.INIT, EngineState.SUBSTITUTED, "Test")
        graph = engine.get_state_graph()
        assert EngineState.INIT in graph

    def test_polymorphic_engine_pass_init(self):
        config = {"seed": 42, "max_iterations": 5}
        p = PolymorphicEnginePass(config)
        assert p.seed == 42
        assert p.max_iterations == 5

    def test_no_op_mutation(self):
        p = NoOp()
        result = p.apply(None)
        assert result["mutations"] == 0


class TestSelfModifyingCode:
    """Tests for self-modifying code module."""

    def test_encryption_scheme_values(self):
        assert EncryptionScheme.XOR_ROLLING.value == "xor_rolling"
        assert EncryptionScheme.XOR_KEY.value == "xor_key"
        assert EncryptionScheme.ADD_SUB.value == "add_sub"
        assert EncryptionScheme.ROL_ROR.value == "rol_ror"
        assert EncryptionScheme.RC4.value == "rc4"

    def test_encrypted_section_creation(self):
        section = EncryptedSection(
            address=0x1000,
            size=64,
            original_bytes=b"\x90" * 64,
        )
        assert section.address == 0x1000
        assert section.size == 64
        assert len(section.original_bytes) == 64

    def test_decrypt_stub_creation(self):
        stub = DecryptStub(
            address=0x2000,
            size=128,
            code=b"\x90" * 128,
        )
        assert stub.address == 0x2000
        assert stub.size == 128

    def test_xor_encrypt(self):
        data = b"Hello, World!"
        key = b"secret"
        encrypted = xor_encrypt(data, key)
        assert encrypted != data

        decrypted = xor_encrypt(encrypted, key)
        assert decrypted == data

    def test_xor_rolling_encrypt(self):
        data = b"Test data"
        initial_key = 0x55
        encrypted, final_key = xor_rolling_encrypt(data, initial_key)
        assert encrypted != data
        assert final_key != initial_key

    def test_add_sub_encrypt(self):
        data = b"ABC"
        key = 0x10
        encrypted = add_sub_encrypt(data, key)
        assert len(encrypted) == len(data)

    def test_rol_encrypt(self):
        data = b"\x01\x02\x03\x04"
        shift = 3
        encrypted = rol_encrypt(data, shift)
        assert len(encrypted) == len(data)

    def test_rc4_crypt(self):
        key = b"secret_key"
        data = b"Data to encrypt"
        encrypted = rc4_crypt(data, key)
        assert len(encrypted) == len(data)
        assert encrypted != data

        decrypted = rc4_crypt(encrypted, key)
        assert decrypted == data

    def test_generate_polymorphic_stub_x64(self):
        key = b"\xaa\xbb\xcc\xdd"
        data_size = 64
        seed = 12345
        stub = generate_polymorphic_stub_x64(key, data_size, seed)
        assert "decrypt_entry" in stub
        assert "encrypted_data" in stub

    def test_self_modifying_code_pass_init(self):
        config = {"probability": 0.5, "max_functions": 5}
        p = SelfModifyingCodePass(config)
        assert p.probability == 0.5
        assert p.max_functions == 5

    def test_create_packed_binary(self):
        code = b"\x90" * 100
        entry = 0x1000
        packed, key, stub = create_packed_binary(code, entry, arch="x64")
        assert len(packed) == len(code)
        assert len(key) == 8
        assert len(stub) > 0


class TestAntiDisassembly:
    """Tests for anti-disassembly module."""

    def test_anti_disasm_type_values(self):
        assert AntiDisasmType.OVERLAPPING.value == "overlapping"
        assert AntiDisasmType.SEH_BASED.value == "seh_based"
        assert AntiDisasmType.JUMP_INTO_MIDDLE.value == "jump_into_middle"
        assert AntiDisasmType.POLYGLOT.value == "polyglot"
        assert AntiDisasmType.FALSE_BRANCH.value == "false_branch"

    def test_anti_disasm_snippet_creation(self):
        snippet = AntiDisasmSnippet(
            asm="nop",
            bytes_hex="90",
            size=1,
            disasm_type=AntiDisasmType.OVERLAPPING,
            description="test",
        )
        assert snippet.size == 1
        assert snippet.disasm_type == AntiDisasmType.OVERLAPPING

    def test_overlapping_snippets_exist(self):
        assert len(OVERLAPPING_X64) > 0
        for snippet in OVERLAPPING_X64:
            assert snippet.disasm_type == AntiDisasmType.OVERLAPPING
            assert len(snippet.bytes_hex) > 0

    def test_jump_middle_snippets_exist(self):
        assert len(JUMP_MIDDLE_X64) > 0
        for snippet in JUMP_MIDDLE_X64:
            assert snippet.disasm_type == AntiDisasmType.JUMP_INTO_MIDDLE

    def test_false_branch_snippets_exist(self):
        assert len(FALSE_BRANCH_X64) > 0
        for snippet in FALSE_BRANCH_X64:
            assert snippet.disasm_type == AntiDisasmType.FALSE_BRANCH

    def test_generate_false_disasm_sequence(self):
        snippet = generate_false_disasm_sequence(arch="x64")
        assert snippet.disasm_type in [
            AntiDisasmType.OVERLAPPING,
            AntiDisasmType.JUMP_INTO_MIDDLE,
            AntiDisasmType.FALSE_BRANCH,
        ]

    def test_generate_opaque_predicate_x64(self):
        predicate = generate_opaque_predicate_x64()
        lower_pred = predicate.lower()
        assert any(jmp in lower_pred for jmp in ["jmp", "jz", "jne", "je", "jnz", "jl", "jg"])

    def test_generate_sled_obfuscation(self):
        sled = generate_sled_obfuscation(size=32)
        assert isinstance(sled, str)
        assert len(sled) > 0

    def test_anti_disassembly_pass_init(self):
        config = {"probability": 0.3, "max_injections": 3}
        p = AntiDisassemblyPass(config)
        assert p.probability == 0.3
        assert p.max_injections == 3

    def test_seh_enabled_option(self):
        p = AntiDisassemblyPass({"seh_enabled": True})
        assert p.seh_enabled is True

        p2 = AntiDisassemblyPass({"seh_enabled": False})
        assert p2.seh_enabled is False
