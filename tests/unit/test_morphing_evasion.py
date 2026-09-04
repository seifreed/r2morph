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

import re

from r2morph.core import randomness
from r2morph.mutations.anti_disassembly import (
    FALSE_BRANCH_X64,
    JUMP_MIDDLE_X64,
    OVERLAPPING_X64,
    AntiDisasmSnippet,
    AntiDisasmType,
    AntiDisassemblyPass,
    generate_false_disasm_sequence,
    generate_opaque_predicate_x64,
    generate_sled_obfuscation,
)
from r2morph.mutations.api_hashing import (
    COMMON_LINUX_APIS,
    COMMON_WINDOWS_APIS,
    HASH_ALGORITHMS,
    APIHashingPass,
    generate_resolver_x64,
    generate_resolver_x86,
    hash_crc32,
    hash_djb2,
    hash_fnv1a,
    hash_ror7,
    hash_ror13,
)
from r2morph.mutations.code_mobility import (
    CodeMobilityPass,
    MobileBlock,
    MobilityPlan,
    calculate_section_offsets,
    estimate_size_with_jumps,
)
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from r2morph.mutations.code_virtualization_dispatch import bytecode_position_mask
from r2morph.mutations.code_virtualization_engine import (
    _interpreter_asm,
    build_vm_scheme,
    decode_instruction,
    encode_bytecode,
    inject_junk_ops,
)
from r2morph.mutations.function_outlining import (
    FunctionOutliningPass,
    OutlinedChunk,
    OutlinedFunction,
    calculate_chunk_layout,
    generate_interleaved_layout,
)
from r2morph.mutations.polymorphic_engine import (
    EngineRunResult,
    EngineState,
    MutationResult,
    NoOp,
    PolymorphicEngine,
    PolymorphicEnginePass,
    StateTransition,
)
from r2morph.mutations.self_modifying_code import (
    DecryptStub,
    EncryptedSection,
    EncryptionScheme,
    SelfModifyingCodePass,
    add_sub_encrypt,
    create_packed_binary,
    generate_polymorphic_stub_x64,
    rc4_crypt,
    rol_encrypt,
    xor_encrypt,
    xor_rolling_encrypt,
)
from r2morph.mutations.stack_strings import (
    EncodingScheme,
    StackStringOptions,
    StackStringsPass,
    add_shift_encode,
    find_printable_strings,
    generate_stack_string_x64,
    generate_stack_string_x86,
    xor_bytes,
    xor_rolling,
)
from tests.utils.assertions import expect

_EXPECTED_BLOCK_GET_JUMP_SIZE_5 = 5
_EXPECTED_BLOCK_ORIGINAL_ADDRESS_4198400 = 0x401000
_EXPECTED_CHUNK_CHUNK_ID_256 = 0x100
_EXPECTED_CHUNK_ORIGINAL_ADDRESS_4198400 = 0x401000
_EXPECTED_ENGINE_SEED_42 = 42
_EXPECTED_FUNC_ORIGINAL_ADDRESS_4198400 = 0x401000
_EXPECTED_LEN_KEY_8 = 8
_EXPECTED_LEN_LAYOUT_3 = 3
_EXPECTED_LEN_OFFSETS_3 = 3
_EXPECTED_LEN_RESULT_4 = 4
_EXPECTED_LEN_SECTION_ORIGINAL_BYTES_64 = 64
_EXPECTED_LEN_STRINGS_0_2 = 2
_EXPECTED_OP_WIDTH_32 = 32
_EXPECTED_P_MAX_BLOCKS_50 = 50
_EXPECTED_P_MAX_FUNCTIONS_10 = 10
_EXPECTED_P_MAX_FUNCTIONS_5 = 5
_EXPECTED_P_MAX_INJECTIONS_3 = 3
_EXPECTED_P_MAX_ITERATIONS_5 = 5
_EXPECTED_P_PROBABILITY_0_3 = 0.3
_EXPECTED_P_PROBABILITY_0_3_2 = 0.3
_EXPECTED_P_PROBABILITY_0_5 = 0.5
_EXPECTED_P_PROBABILITY_0_5_2 = 0.5
_EXPECTED_P_PROBABILITY_0_5_3 = 0.5
_EXPECTED_P_PROBABILITY_0_5_4 = 0.5
_EXPECTED_P_SEED_42 = 42
_EXPECTED_RESULT_ITERATIONS_5 = 5
_EXPECTED_SECTION_ADDRESS_4096 = 0x1000
_EXPECTED_SECTION_SIZE_64 = 64
_EXPECTED_STUB_ADDRESS_8192 = 0x2000
_EXPECTED_STUB_SIZE_128 = 128


class TestAPIHashing:
    """Tests for API hashing functions."""

    def test_hash_ror13_known_values(self):
        result = hash_ror13("CreateFileA")
        expect(isinstance(result, int))
        expect(not (result <= 0))

    def test_hash_ror13_case_insensitive(self):
        expect(hash_ror13("CreateFileA") == hash_ror13("createfilea"))

    def test_hash_ror7_different_from_ror13(self):
        expect(hash_ror7("test") != hash_ror13("test"))

    def test_hash_djb2_known(self):
        result = hash_djb2("test")
        expect(isinstance(result, int))
        expect(not (result <= 0))

    def test_hash_fnv1a_known(self):
        result = hash_fnv1a("test")
        expect(isinstance(result, int))
        expect(not (result <= 0))

    def test_hash_crc32_known(self):
        result = hash_crc32("test")
        expect(isinstance(result, int))
        expect(not (result < 0))

    def test_hash_algorithms_dict(self):
        expect(not ("ror13" not in HASH_ALGORITHMS))
        expect(not ("ror7" not in HASH_ALGORITHMS))
        expect(not ("djb2" not in HASH_ALGORITHMS))
        expect(not ("fnv1a" not in HASH_ALGORITHMS))
        expect(not ("crc32" not in HASH_ALGORITHMS))

    def test_common_apis_lists(self):
        expect(not ("CreateFileA" not in COMMON_WINDOWS_APIS))
        expect(not ("VirtualAlloc" not in COMMON_WINDOWS_APIS))
        expect(not ("open" not in COMMON_LINUX_APIS))
        expect(not ("mmap" not in COMMON_LINUX_APIS))

    def test_generate_resolver_x64(self):
        asm = generate_resolver_x64(0x12345678)
        expect(not ("resolve_api" not in asm))
        expect(not ("gs:[0x60]" not in asm))
        expect("PEB" in asm or "ldr" in asm.lower())

    def test_generate_resolver_x86(self):
        asm = generate_resolver_x86(0x12345678)
        expect(not ("resolve_api" not in asm))
        expect(not ("fs:[0x30]" not in asm))

    def test_api_hashing_pass_init(self):
        config = {"hash_algorithm": "ror13", "arch": "x64"}
        p = APIHashingPass(config)
        expect(p.hash_algorithm == "ror13")
        expect(p.arch == "x64")

    def test_api_hashing_pass_get_hashes(self):
        p = APIHashingPass()
        hashes = p.get_api_hashes()
        expect(isinstance(hashes, dict))
        expect(not (len(hashes) <= 0))
        expect(all(isinstance(v, int) for v in hashes.values()))


class TestStackStrings:
    """Tests for stack string functions."""

    def test_encoding_scheme_values(self):
        expect(EncodingScheme.PLAIN == "plain")
        expect(EncodingScheme.XOR_SINGLE == "xor_single")
        expect(EncodingScheme.XOR_ROLLING == "xor_rolling")
        expect(EncodingScheme.ADD_SHIFT == "add_shift")

    def test_xor_bytes(self):
        data = b"Hello"
        result = xor_bytes(data, 0x55)
        expect(len(result) == len(data))
        expect(result != data)
        recovered = xor_bytes(result, 0x55)
        expect(recovered == data)

    def test_xor_rolling(self):
        data = b"Hello"
        result, _final_key = xor_rolling(data, 0x42)
        expect(len(result) == len(data))
        expect(result != data)

    def test_add_shift_encode(self):
        data = b"Hello"
        result = add_shift_encode(data, 5)
        expect(len(result) == len(data))
        expect(result != data)

    def test_find_printable_strings(self):
        data = b"Hello\x00World\x00Test\x00"
        strings = find_printable_strings(data, min_length=4)
        expect(not (len(strings) < 1))
        expect(len(strings[0]) == _EXPECTED_LEN_STRINGS_0_2)
        expect(strings[0][1] == b"Hello" or strings[0][1].startswith(b"Hello"))

    def test_generate_stack_string_x64_plain(self):
        string_data = b"Hello"
        asm, _junk = generate_stack_string_x64(string_data, StackStringOptions(encoding=EncodingScheme.PLAIN))
        expect(not ("sub rsp" not in asm))
        expect(not ("mov byte" not in asm))

    def test_generate_stack_string_x64_xor(self):
        string_data = b"Hello"
        asm, _junk = generate_stack_string_x64(
            string_data,
            StackStringOptions(encoding=EncodingScheme.XOR_SINGLE, xor_key=0x55),
        )
        expect(not ("sub rsp" not in asm))
        expect(not ("xor" not in asm))

    def test_generate_stack_string_x86_plain(self):
        string_data = b"Test"
        asm, _junk = generate_stack_string_x86(string_data, StackStringOptions(encoding=EncodingScheme.PLAIN))
        expect(not ("sub esp" not in asm))
        expect(not ("mov byte" not in asm))

    def test_generate_stack_string_with_junk(self):
        string_data = b"Test"
        _asm, junk = generate_stack_string_x64(
            string_data,
            StackStringOptions(
                encoding=EncodingScheme.PLAIN,
                interleave_junk=True,
                junk_probability=1.0,
            ),
        )
        expect(not (len(junk) <= 0))

    def test_stack_strings_pass_init(self):
        config = {"probability": 0.5, "encoding": "xor_single"}
        p = StackStringsPass(config)
        expect(p.probability == _EXPECTED_P_PROBABILITY_0_5)
        expect(p.encoding == "xor_single")

    def test_stack_strings_pass_preview(self):
        p = StackStringsPass()
        asm = p.preview_string("Hello World")
        expect(not ("sub rsp" not in asm))


class TestCodeVirtualization:
    """Tests for the code-virtualization engine and pass surface."""

    def test_decode_instruction_accepts_64bit_register_op(self):
        op = decode_instruction("add rbx, rcx")
        expect(op is not None and op.mnemonic == "add" and not op.is_immediate)

    def test_decode_instruction_accepts_32bit_register_with_width(self):
        op = decode_instruction("mov eax, 1")
        expect(op is not None and op.width == _EXPECTED_OP_WIDTH_32)

    def test_decode_instruction_rejects_mismatched_operand_widths(self):
        expect(not (decode_instruction("add eax, rbx") is not None))

    def test_decode_instruction_rejects_memory_operand(self):
        expect(not (decode_instruction("mov rax, qword ptr [rbx]") is not None))

    def test_encode_bytecode_is_encrypted_and_decrypts_to_exit(self):
        ops = [decode_instruction("mov rax, 0x3c"), decode_instruction("xor rdi, rdi")]
        expect(all(ops))
        scheme = build_vm_scheme(randomness.Random(1))
        checksum = 0xA7
        bytecode = encode_bytecode(ops, scheme, checksum=checksum)
        # The exit opcode is masked with the progressive stream value for its
        # offset, then XOR-encrypted with the runtime self-checksum.
        position = bytecode_position_mask(len(bytecode) - 1)
        expect(bytecode[-1] ^ checksum ^ position == scheme.exit_opcode)

    def test_build_vm_scheme_is_polymorphic(self):
        first = build_vm_scheme(randomness.Random(1))
        second = build_vm_scheme(randomness.Random(2))
        expect((first.dup, first.xor_key) != (second.dup, second.xor_key))

    def test_build_vm_scheme_duplicates_some_operations(self):
        # Opcode polymorphism: at least one operation must map to more than one
        # opcode so the opcode->operation map is many-to-one (not a 1:1 table an
        # analyst can read off by opcode frequency). Parity with the region VM.
        scheme = build_vm_scheme(randomness.Random(3))
        expect(any(len(indices) > 1 for indices in scheme.dup.values()))

    def test_duplicate_handlers_diverge_with_head_junk(self):
        # Duplicate handler instances must not be byte-identical, or an analyst
        # collapses them and recovers the operation set; reachable head junk
        # (rbx/rbp/r12) diverges them. With duplication present, the interpreter
        # carries more handler instances than distinct operations.
        scheme = build_vm_scheme(randomness.Random(3))
        total = sum(len(indices) for indices in scheme.dup.values())
        expect(not (total <= len(scheme.dup)))
        asm = _interpreter_asm(0x401000, scheme)
        expect(not (f"h_{total - 1}:" not in asm))

    def test_inject_junk_ops_adds_identity_movs_preserving_real_ops(self):
        # Junk padding must be identity mov reg,reg (semantics-preserving) and must
        # keep the run's real ops in their original order between the junk.
        real = [decode_instruction("mov rax, rbx"), decode_instruction("add rax, 1")]
        expect(all(real))
        padded = inject_junk_ops(real, randomness.Random(1))
        expect(not (len(padded) <= len(real)))
        expect([op for op in padded if not (op.mnemonic == "mov" and op.dst_index == op.value)] == real)
        added = [op for op in padded if op.mnemonic == "mov" and op.dst_index == op.value]
        expect(added)

    def test_arithmetic_handlers_contain_no_literal_native_op(self):
        # The arithmetic/boolean handlers must compute via MBA, not a literal
        # add/sub/xor/and/or against a guest cell, so the handler never names the
        # operation it performs (the engine's flags-dead precondition makes this
        # unconditionally safe). mov stays a verbatim store. A literal guest op
        # would read its operand straight from a slot/vstack cell in memory, so the
        # memory-operand form is the rename-stable signature to forbid; the exact
        # MBA/micro-op lowering is pinned by the dedicated mba/microops tests. (A
        # register-operand proxy would be unsound now that per-handler renaming can
        # reorder the immediate-decrypt xor into an arbitrary reg,reg spelling.)
        scheme = build_vm_scheme(randomness.Random(3))
        asm = _interpreter_asm(0x401000, scheme)
        for op in ("add", "sub", "xor", "and", "or"):
            expect(f"{op} qword ptr [rsp" not in asm)
            expect(f"{op} dword ptr [rsp" not in asm)

    def test_scheme_generates_nonzero_table_key(self):
        scheme = build_vm_scheme(randomness.Random(3))
        expect(1 <= scheme.table_key < (1 << 32))

    def test_dispatch_decrypts_the_table_without_exposing_a_constant_key(self):
        # The dispatch decrypts each loaded table offset with the self-checksum
        # broadcast alone (see the diffuse test below), so the handler table is not a
        # plaintext switch a disassembler can recover, yet no build-constant table key
        # is XORed into eax -- the decode exposes no table-key literal a decompiler
        # could read off the pseudocode (parity with the region VM).
        scheme = build_vm_scheme(randomness.Random(3))
        asm = _interpreter_asm(0x401000, scheme)
        expect(f"xor eax, {hex(scheme.table_key)}" not in asm)

    def test_dispatch_diffuses_the_table_key_with_the_self_checksum(self):
        # The table-entry decrypt also folds the runtime self-checksum (broadcast
        # to 32 bits), so tampering corrupts handler resolution, not just opcodes.
        scheme = build_vm_scheme(randomness.Random(3))
        asm = _interpreter_asm(0x401000, scheme)
        expect(not ("imul ecx, ecx, 0x1010101" not in asm))

    def test_handlers_position_unmask_their_operands(self):
        # Operands carry the opcode's stream position, so the handler un-masks the
        # destination slot with r13b (the position) - not a lone constant key. The
        # scratch register holding the operand byte is renamed per handler, so match
        # any numbered scratch byte (the decode uses ``al`` for the opcode, so this
        # only matches a handler's operand un-mask, not the dispatch).
        scheme = build_vm_scheme(randomness.Random(3))
        asm = _interpreter_asm(0x401000, scheme)
        expect(re.search(r"xor r\d+b, r13b", asm))

    def test_code_virtualization_pass_init(self):
        p = CodeVirtualizationPass({"probability": 0.5})
        expect(p.probability == _EXPECTED_P_PROBABILITY_0_5_2)


class TestFunctionOutlining:
    """Tests for function outlining functions."""

    def test_outlined_chunk_creation(self):
        chunk = OutlinedChunk(
            chunk_id=0x100,
            original_address=0x401000,
            instructions=[],
            section=".outlined",
        )
        expect(chunk.chunk_id == _EXPECTED_CHUNK_CHUNK_ID_256)
        expect(chunk.original_address == _EXPECTED_CHUNK_ORIGINAL_ADDRESS_4198400)

    def test_outlined_chunk_to_asm(self):
        chunk = OutlinedChunk(
            chunk_id=0x100,
            original_address=0x401000,
            instructions=[{"disasm": "mov eax, 1"}, {"disasm": "ret"}],
        )
        asm = chunk.to_asm()
        expect(not ("chunk_0100:" not in asm))
        expect(not ("mov eax, 1" not in asm))

    def test_outlined_function_creation(self):
        func = OutlinedFunction(
            original_address=0x401000,
            original_name="test_func",
        )
        expect(func.original_address == _EXPECTED_FUNC_ORIGINAL_ADDRESS_4198400)
        expect(len(func.chunks) == 0)

    def test_outlined_function_add_chunk(self):
        func = OutlinedFunction(original_address=0x401000, original_name="test_func")
        chunk = OutlinedChunk(chunk_id=0x100, original_address=0x401000, instructions=[])
        func.add_chunk(chunk)
        expect(len(func.chunks) == 1)

    def test_outlined_function_get_chunk_order(self):
        func = OutlinedFunction(original_address=0x401000, original_name="test_func")
        for i in range(3):
            chunk = OutlinedChunk(chunk_id=i, original_address=0x401000 + i * 0x100, instructions=[])
            func.chunks.append(chunk)
        order = func.get_chunk_order()
        expect(not (len(order) < 0))

    def test_function_outlining_pass_init(self):
        config = {"probability": 0.5, "max_functions": 10}
        p = FunctionOutliningPass(config)
        expect(p.probability == _EXPECTED_P_PROBABILITY_0_5_3)
        expect(p.max_functions == _EXPECTED_P_MAX_FUNCTIONS_10)

    def test_calculate_chunk_layout(self):
        chunks = [OutlinedChunk(chunk_id=i, original_address=i * 0x100, instructions=[]) for i in range(3)]
        layout = calculate_chunk_layout(chunks)
        expect(len(layout) == _EXPECTED_LEN_LAYOUT_3)

    def test_generate_interleaved_layout(self):
        func1 = OutlinedFunction(original_address=0x1000, original_name="f1")
        func2 = OutlinedFunction(original_address=0x2000, original_name="f2")
        for i in range(2):
            func1.chunks.append(OutlinedChunk(chunk_id=i, original_address=0x1000 + i * 0x100, instructions=[]))
            func2.chunks.append(OutlinedChunk(chunk_id=100 + i, original_address=0x2000 + i * 0x100, instructions=[]))
        result = generate_interleaved_layout([func1, func2], seed=42)
        expect(len(result) == _EXPECTED_LEN_RESULT_4)


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
        expect(block.block_id == 0)
        expect(block.original_address == _EXPECTED_BLOCK_ORIGINAL_ADDRESS_4198400)

    def test_mobile_block_get_jump_size(self):
        block = MobileBlock(block_id=0, original_address=0x1000, original_section=".text", size=100)
        expect(block.get_jump_size() == _EXPECTED_BLOCK_GET_JUMP_SIZE_5)

    def test_mobility_plan_creation(self):
        plan = MobilityPlan()
        expect(len(plan.blocks) == 0)

    def test_mobility_plan_add_block(self):
        plan = MobilityPlan()
        block = MobileBlock(
            block_id=0, original_address=0x1000, original_section=".text", size=32, target_section=".mobile_0"
        )
        plan.add_block(block)
        expect(len(plan.blocks) == 1)
        expect(not (".mobile_0" not in plan.section_layout))

    def test_code_mobility_pass_init(self):
        config = {"probability": 0.3, "max_blocks": 50}
        p = CodeMobilityPass(config)
        expect(p.probability == _EXPECTED_P_PROBABILITY_0_3)
        expect(p.max_blocks == _EXPECTED_P_MAX_BLOCKS_50)

    def test_calculate_section_offsets(self):
        sections = [".mobile_0", ".mobile_1", ".mobile_2"]
        offsets = calculate_section_offsets(sections)
        expect(len(offsets) == _EXPECTED_LEN_OFFSETS_3)
        expect(all(addr > 0 for addr in offsets.values()))

    def test_estimate_size_with_jumps(self):
        blocks = [
            MobileBlock(block_id=i, original_address=i * 0x100, original_section=".text", size=32) for i in range(3)
        ]
        size = estimate_size_with_jumps(blocks)
        expect(not (size <= sum(b.size for b in blocks)))


class TestPolymorphicEngine:
    """Tests for polymorphic engine functions."""

    def test_engine_state_values(self):
        expect(hasattr(EngineState, "INIT"))
        expect(hasattr(EngineState, "FINAL"))
        expect(hasattr(EngineState, "SUBSTITUTED"))

    def test_state_transition_creation(self):
        trans = StateTransition(
            from_state=EngineState.INIT,
            to_state=EngineState.SUBSTITUTED,
            mutation_name="TestMutation",
        )
        expect(trans.from_state == EngineState.INIT)
        expect(trans.to_state == EngineState.SUBSTITUTED)

    def test_mutation_result_creation(self):
        result = MutationResult(
            name="Test",
            state_before=EngineState.INIT,
            state_after=EngineState.SUBSTITUTED,
            success=True,
        )
        expect(not (result.success is not True))
        expect(result.name == "Test")

    def test_engine_run_result_creation(self):
        result = EngineRunResult(
            initial_state=EngineState.INIT,
            final_state=EngineState.FINAL,
            iterations=5,
        )
        expect(result.iterations == _EXPECTED_RESULT_ITERATIONS_5)
        expect(not (result.converged is not False))

    def test_polymorphic_engine_init(self):
        engine = PolymorphicEngine(seed=42)
        expect(engine.seed == _EXPECTED_ENGINE_SEED_42)
        expect(engine.current_state == EngineState.INIT)

    def test_polymorphic_engine_add_mutation(self):
        engine = PolymorphicEngine()
        mutation = NoOp()
        engine.add_mutation("test", mutation)
        expect(not ("test" not in engine.mutations))

    def test_polymorphic_engine_add_transition(self):
        engine = PolymorphicEngine()
        engine.add_transition(EngineState.INIT, EngineState.SUBSTITUTED, "TestMutation")
        expect(not (EngineState.INIT not in engine.transitions))
        expect(len(engine.transitions[EngineState.INIT]) == 1)

    def test_polymorphic_engine_get_available_transitions(self):
        engine = PolymorphicEngine()
        engine.add_transition(EngineState.INIT, EngineState.SUBSTITUTED, "Test")
        available = engine.get_available_transitions(EngineState.INIT)
        expect(len(available) == 1)

    def test_polymorphic_engine_get_state_graph(self):
        engine = PolymorphicEngine()
        engine.add_transition(EngineState.INIT, EngineState.SUBSTITUTED, "Test")
        graph = engine.get_state_graph()
        expect(not (EngineState.INIT not in graph))

    def test_polymorphic_engine_pass_init(self):
        config = {"seed": 42, "max_iterations": 5}
        p = PolymorphicEnginePass(config)
        expect(p.seed == _EXPECTED_P_SEED_42)
        expect(p.max_iterations == _EXPECTED_P_MAX_ITERATIONS_5)

    def test_no_op_mutation(self):
        p = NoOp()
        result = p.apply(None)
        # `mutations` is the list of mutation records (Pipeline len()s and
        # iterates it; base.run only setdefaults it when absent). The old
        # `== 0` assertion pinned a contract violation that crashed the
        # pipeline with "object of type 'int' has no len()"; a no-op
        # contributes zero mutations -> empty list.
        expect(result["mutations"] == [])


class TestSelfModifyingCode:
    """Tests for self-modifying code module."""

    def test_encryption_scheme_values(self):
        expect(EncryptionScheme.XOR_ROLLING.value == "xor_rolling")
        expect(EncryptionScheme.XOR_KEY.value == "xor_key")
        expect(EncryptionScheme.ADD_SUB.value == "add_sub")
        expect(EncryptionScheme.ROL_ROR.value == "rol_ror")
        expect(EncryptionScheme.RC4.value == "rc4")

    def test_encrypted_section_creation(self):
        section = EncryptedSection(
            address=0x1000,
            size=64,
            original_bytes=b"\x90" * 64,
        )
        expect(section.address == _EXPECTED_SECTION_ADDRESS_4096)
        expect(section.size == _EXPECTED_SECTION_SIZE_64)
        expect(len(section.original_bytes) == _EXPECTED_LEN_SECTION_ORIGINAL_BYTES_64)

    def test_decrypt_stub_creation(self):
        stub = DecryptStub(
            address=0x2000,
            size=128,
            code=b"\x90" * 128,
        )
        expect(stub.address == _EXPECTED_STUB_ADDRESS_8192)
        expect(stub.size == _EXPECTED_STUB_SIZE_128)

    def test_xor_encrypt(self):
        data = b"Hello, World!"
        key = b"secret"
        encrypted = xor_encrypt(data, key)
        expect(encrypted != data)

        decrypted = xor_encrypt(encrypted, key)
        expect(decrypted == data)

    def test_xor_rolling_encrypt(self):
        data = b"Test data"
        initial_key = 0x55
        encrypted, final_key = xor_rolling_encrypt(data, initial_key)
        expect(encrypted != data)
        expect(final_key != initial_key)

    def test_add_sub_encrypt(self):
        data = b"ABC"
        key = 0x10
        encrypted = add_sub_encrypt(data, key)
        expect(len(encrypted) == len(data))

    def test_rol_encrypt(self):
        data = b"\x01\x02\x03\x04"
        shift = 3
        encrypted = rol_encrypt(data, shift)
        expect(len(encrypted) == len(data))

    def test_rc4_crypt(self):
        key = b"secret_key"
        data = b"Data to encrypt"
        encrypted = rc4_crypt(data, key)
        expect(len(encrypted) == len(data))
        expect(encrypted != data)

        decrypted = rc4_crypt(encrypted, key)
        expect(decrypted == data)

    def test_generate_polymorphic_stub_x64(self):
        key = b"\xaa\xbb\xcc\xdd"
        data_size = 64
        seed = 12345
        stub = generate_polymorphic_stub_x64(key, data_size, seed)
        expect(not ("decrypt_entry" not in stub))
        expect(not ("encrypted_data" not in stub))

    def test_self_modifying_code_pass_init(self):
        config = {"probability": 0.5, "max_functions": 5}
        p = SelfModifyingCodePass(config)
        expect(p.probability == _EXPECTED_P_PROBABILITY_0_5_4)
        expect(p.max_functions == _EXPECTED_P_MAX_FUNCTIONS_5)

    def test_create_packed_binary(self):
        code = b"\x90" * 100
        packed, key, stub = create_packed_binary(code, arch="x64")
        expect(len(packed) == len(code))
        expect(len(key) == _EXPECTED_LEN_KEY_8)
        expect(not (len(stub) <= 0))


class TestAntiDisassembly:
    """Tests for anti-disassembly module."""

    def test_anti_disasm_type_values(self):
        expect(AntiDisasmType.OVERLAPPING.value == "overlapping")
        expect(AntiDisasmType.SEH_BASED.value == "seh_based")
        expect(AntiDisasmType.JUMP_INTO_MIDDLE.value == "jump_into_middle")
        expect(AntiDisasmType.POLYGLOT.value == "polyglot")
        expect(AntiDisasmType.FALSE_BRANCH.value == "false_branch")

    def test_anti_disasm_snippet_creation(self):
        snippet = AntiDisasmSnippet(
            asm="nop",
            bytes_hex="90",
            size=1,
            disasm_type=AntiDisasmType.OVERLAPPING,
            description="test",
        )
        expect(snippet.size == 1)
        expect(snippet.disasm_type == AntiDisasmType.OVERLAPPING)

    def test_overlapping_snippets_exist(self):
        expect(not (len(OVERLAPPING_X64) <= 0))
        for snippet in OVERLAPPING_X64:
            expect(snippet.disasm_type == AntiDisasmType.OVERLAPPING)
            expect(not (len(snippet.bytes_hex) <= 0))

    def test_jump_middle_snippets_exist(self):
        expect(not (len(JUMP_MIDDLE_X64) <= 0))
        for snippet in JUMP_MIDDLE_X64:
            expect(snippet.disasm_type == AntiDisasmType.JUMP_INTO_MIDDLE)

    def test_false_branch_snippets_exist(self):
        expect(not (len(FALSE_BRANCH_X64) <= 0))
        for snippet in FALSE_BRANCH_X64:
            expect(snippet.disasm_type == AntiDisasmType.FALSE_BRANCH)

    def test_generate_false_disasm_sequence(self):
        snippet = generate_false_disasm_sequence(arch="x64")
        expect(
            not (
                snippet.disasm_type
                not in [
                    AntiDisasmType.OVERLAPPING,
                    AntiDisasmType.JUMP_INTO_MIDDLE,
                    AntiDisasmType.FALSE_BRANCH,
                ]
            )
        )

    def test_generate_opaque_predicate_x64(self):
        predicate = generate_opaque_predicate_x64()
        lower_pred = predicate.lower()
        expect(any(jmp in lower_pred for jmp in ["jmp", "jz", "jne", "je", "jnz", "jl", "jg"]))

    def test_generate_sled_obfuscation(self):
        sled = generate_sled_obfuscation(size=32)
        expect(isinstance(sled, str))
        expect(not (len(sled) <= 0))

    def test_anti_disassembly_pass_init(self):
        config = {"probability": 0.3, "max_injections": 3}
        p = AntiDisassemblyPass(config)
        expect(p.probability == _EXPECTED_P_PROBABILITY_0_3_2)
        expect(p.max_injections == _EXPECTED_P_MAX_INJECTIONS_3)

    def test_seh_enabled_option(self):
        p = AntiDisassemblyPass({"seh_enabled": True})
        expect(not (p.seh_enabled is not True))

        p2 = AntiDisassemblyPass({"seh_enabled": False})
        expect(not (p2.seh_enabled is not False))
