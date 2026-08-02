"""
VM handler analyzer for identifying and classifying virtual machine handlers.

This module identifies VM handlers in virtualized binaries and classifies
their semantic behavior using pattern matching and symbolic execution.
"""

import logging
from typing import Any

from r2morph.analysis.cfg import CFGBuilder

from .vm_handler_metrics import build_handler_statistics, calculate_handler_confidence
from .vm_handler_models import VMArchitecture, VMHandler, VMHandlerType
from .vm_handler_patterns import load_vm_handler_patterns

logger = logging.getLogger(__name__)

# r2 instruction types for a register/memory-indirect jump - the defining
# dispatch instruction of a computed-goto VM (jmp reg / jmp [table + idx*scale]).
_INDIRECT_JUMP_TYPES = frozenset({"ujmp", "rjmp", "mjmp", "ijmp"})


class VMHandlerAnalyzer:
    """
    Analyzer for identifying and classifying VM handlers.

    Uses pattern matching, control flow analysis, and semantic analysis
    to identify VM handlers and understand their behavior.
    """

    def __init__(self, binary: Any) -> None:
        """
        Initialize VM handler analyzer.

        Args:
            binary: Binary to analyze (can be None for deferred binding)
        """
        self.binary = binary
        self.vm_architecture: VMArchitecture | None = None
        self.handler_patterns = load_vm_handler_patterns()

    def analyze_vm_architecture(self, suspected_dispatcher: int) -> VMArchitecture:
        """
        Analyze the overall VM architecture starting from a suspected dispatcher.

        Args:
            suspected_dispatcher: Address of suspected VM dispatcher

        Returns:
            VM architecture analysis
        """
        logger.info(f"Analyzing VM architecture from dispatcher at 0x{suspected_dispatcher:x}")

        self.vm_architecture = VMArchitecture(dispatcher_address=suspected_dispatcher)

        # 1. Analyze dispatcher to find handler table
        handler_table = self._find_handler_table(suspected_dispatcher)
        if handler_table:
            self.vm_architecture.handler_table_address = handler_table
            logger.info(f"Found handler table at 0x{handler_table:x}")

        # 2. Extract handler addresses from table
        handler_addresses = self._extract_handler_addresses(handler_table)
        logger.info(f"Found {len(handler_addresses)} potential handlers")

        # 3. Analyze each handler
        for i, addr in enumerate(handler_addresses):
            handler = self._analyze_single_handler(i, addr)
            if handler:
                self.vm_architecture.handlers[i] = handler

        # 4. Identify VM context and registers
        self._analyze_vm_context()

        # 5. Try to locate bytecode
        self._locate_vm_bytecode()

        logger.info(f"VM analysis complete: {len(self.vm_architecture.handlers)} handlers identified")
        return self.vm_architecture

    def _find_handler_table(self, dispatcher_addr: int) -> int | None:
        """
        Find the VM handler table from the dispatcher.

        Args:
            dispatcher_addr: Dispatcher function address

        Returns:
            Handler table address or None
        """
        try:
            # Analyze dispatcher instructions
            instructions = self.binary.get_function_disasm(dispatcher_addr)

            for inst in instructions:
                disasm = inst.get("disasm", "")

                # Look for table access patterns
                # Common pattern: mov reg, [table + index*scale]
                if "mov" in disasm and "[" in disasm and "+" in disasm:
                    # Extract potential table address
                    import re

                    # Pattern for address constants
                    addr_pattern = r"0x([0-9a-fA-F]+)"
                    matches = re.findall(addr_pattern, disasm)

                    for match in matches:
                        try:
                            addr = int(match, 16)
                            # Validate if this looks like a valid table address
                            if self._validate_handler_table(addr):
                                return addr
                        except ValueError:
                            continue

            # Alternative: a dispatch block reaches its handlers through a
            # register-indirect jump indexing a table (jmp [table + idx*scale]).
            # r2 does not resolve such a jump to a static successor set, so the
            # table base must be recovered from the jump's own memory operand.
            cfg_builder = CFGBuilder(self.binary)
            cfg = cfg_builder.build_cfg(dispatcher_addr)

            for block_addr, block in cfg.blocks.items():
                table = self._extract_table_from_block(block_addr, block.size)
                if table is not None:
                    return table

        except Exception as e:
            logger.debug(f"Error finding handler table: {e}")

        return None

    def _validate_handler_table(self, table_addr: int) -> bool:
        """
        Validate if an address points to a valid handler table.

        Args:
            table_addr: Potential table address

        Returns:
            True if address appears to be a handler table
        """
        try:
            # Read potential table entries
            arch_info = self.binary.get_arch_info()
            ptr_size = arch_info["bits"] // 8

            entries = []
            max_addr = (1 << arch_info["bits"]) - 1 if arch_info["bits"] >= 32 else 0xFFFFFFFF
            for i in range(0, min(256, 64) * ptr_size, ptr_size):  # Check up to 64 entries
                assert self.binary.r2 is not None
                try:
                    entry_hex = self.binary.r2.cmd(f"p8 {ptr_size} @ {table_addr + i}")
                    entry_bytes = bytes.fromhex(entry_hex.strip())

                    if ptr_size == 8:
                        entry = int.from_bytes(entry_bytes, "little")
                    else:
                        entry = int.from_bytes(entry_bytes, "little")

                    entries.append(entry)

                    # Stop if we hit a clearly invalid address
                    if entry == 0 or entry > max_addr:
                        break

                except Exception as e:
                    logger.debug(f"Failed to read table entry: {e}")
                    break

            # Validate entries look like code addresses
            valid_entries = 0
            for entry in entries[:20]:  # Check first 20 entries
                if self._is_valid_code_address(entry):
                    valid_entries += 1

            # At least 50% should be valid code addresses
            return len(entries) >= 4 and (valid_entries / len(entries)) >= 0.5

        except Exception as e:
            logger.debug(f"Error validating handler table: {e}")
            return False

    def _is_valid_code_address(self, addr: int) -> bool:
        """Check if address points to valid code."""
        assert self.binary.r2 is not None
        try:
            # Try to disassemble one instruction at this address
            disasm = self.binary.r2.cmd(f"pd 1 @ {addr}")
            return len(disasm.strip()) > 0 and "invalid" not in disasm.lower()
        except Exception as e:
            logger.debug(f"Failed to validate code address 0x{addr:x}: {e}")
            return False

    def _extract_table_from_block(self, block_addr: int, block_size: int) -> int | None:
        """Recover a handler-table address from a dispatch block.

        A computed-goto dispatcher reaches its handlers through a register-
        indirect jump that indexes a table (``jmp [table + idx*scale]``). The
        table base is that jump's memory-operand pointer; validate it as a
        handler table before trusting it.
        """
        assert self.binary.r2 is not None
        try:
            instructions = self.binary.r2.cmdj(f"pDj {block_size} @ {block_addr}") or []
        except Exception as e:
            logger.debug(f"Failed to disassemble block at 0x{block_addr:x}: {e}")
            return None

        for insn in instructions:
            if insn.get("type") not in _INDIRECT_JUMP_TYPES:
                continue
            table_addr = insn.get("ptr")
            if isinstance(table_addr, int) and table_addr > 0 and self._validate_handler_table(table_addr):
                return table_addr

        return None

    def _extract_handler_addresses(self, table_addr: int | None) -> list[int]:
        """
        Extract handler addresses from the handler table.

        Args:
            table_addr: Handler table address

        Returns:
            List of handler addresses
        """
        if not table_addr:
            return []

        addresses = []

        try:
            arch_info = self.binary.get_arch_info()
            ptr_size = arch_info["bits"] // 8

            # Read table entries
            max_addr = (1 << arch_info["bits"]) - 1 if arch_info["bits"] >= 32 else 0xFFFFFFFF
            for i in range(0, 256 * ptr_size, ptr_size):  # Up to 256 handlers
                assert self.binary.r2 is not None
                try:
                    entry_hex = self.binary.r2.cmd(f"p8 {ptr_size} @ {table_addr + i}")
                    entry_bytes = bytes.fromhex(entry_hex.strip())

                    if len(entry_bytes) != ptr_size:
                        break

                    entry = int.from_bytes(entry_bytes, "little")

                    # Stop at null or invalid entries
                    if entry == 0 or entry > max_addr:
                        break

                    if self._is_valid_code_address(entry):
                        addresses.append(entry)
                    else:
                        break

                except Exception as e:
                    logger.debug(f"Failed to read handler entry: {e}")
                    break

            logger.info(f"Extracted {len(addresses)} handler addresses from table")

        except Exception as e:
            logger.error(f"Error extracting handler addresses: {e}")

        return addresses

    def _analyze_single_handler(self, handler_id: int, address: int) -> VMHandler | None:
        """
        Analyze a single VM handler.

        Args:
            handler_id: Unique handler ID
            address: Handler address

        Returns:
            Analyzed VM handler or None
        """
        try:
            logger.debug(f"Analyzing handler {handler_id} at 0x{address:x}")

            # Get handler instructions
            instructions = self._get_handler_instructions(address)
            if not instructions:
                return None

            handler = VMHandler(
                handler_id=handler_id,
                entry_address=address,
                size=len(instructions) * 4,  # Rough estimate
                instructions=instructions,
            )

            # Classify handler type
            handler.handler_type = self._classify_handler_type(instructions)

            # Generate semantic signature
            handler.semantic_signature = self._generate_semantic_signature(instructions)

            # Generate equivalent x86 if possible
            handler.equivalent_x86 = self._generate_equivalent_x86(handler)

            # Calculate confidence
            handler.confidence = self._calculate_handler_confidence(handler)

            return handler

        except Exception as e:
            logger.debug(f"Error analyzing handler {handler_id}: {e}")
            return None

    def _get_handler_instructions(self, address: int) -> list[dict[str, Any]]:
        """Get instructions for a VM handler."""
        assert self.binary.r2 is not None
        try:
            # Try to get function disassembly
            instructions: list[dict[str, Any]] = self.binary.get_function_disasm(address)

            if not instructions:
                # Fallback: disassemble a fixed number of instructions
                disasm_output = self.binary.r2.cmd(f"pd 20 @ {address}")
                # Parse disassembly output (simplified)
                instructions = []
                for line in disasm_output.split("\n"):
                    if line.strip() and not line.startswith(";"):
                        instructions.append({"disasm": line.strip()})

            return instructions

        except Exception as e:
            logger.debug(f"Error getting handler instructions: {e}")
            return []

    def _classify_handler_type(self, instructions: list[dict[str, Any]]) -> VMHandlerType:
        """
        Classify handler type based on instruction patterns.

        Args:
            instructions: Handler instructions

        Returns:
            Classified handler type
        """
        # Combine all instruction text for pattern matching
        instruction_text = " ".join(inst.get("disasm", "").lower() for inst in instructions)

        # Score each handler type
        type_scores = {}

        for handler_type, patterns in self.handler_patterns.items():
            score = 0.0

            for pattern_info in patterns:
                pattern_list = pattern_info["pattern"]
                confidence = pattern_info["confidence"]

                for pattern in pattern_list:
                    if isinstance(pattern, str):
                        if pattern in instruction_text:
                            score += confidence
                    # Could add regex pattern matching here

            type_scores[handler_type] = score

        # Return type with highest score
        if type_scores:
            best_type = max(type_scores, key=lambda k: type_scores[k])
            if type_scores[best_type] > 0:
                return best_type

        return VMHandlerType.UNKNOWN

    def _generate_semantic_signature(self, instructions: list[dict[str, Any]]) -> str:
        """Generate semantic signature for handler."""
        # Simple signature based on instruction mnemonics
        mnemonics = []

        for inst in instructions:
            disasm = inst.get("disasm", "")
            if disasm:
                # Extract mnemonic (first word)
                parts = disasm.split()
                if parts:
                    mnemonics.append(parts[0])

        return " -> ".join(mnemonics[:10])  # Limit to first 10 instructions

    def _generate_equivalent_x86(self, handler: VMHandler) -> str | None:
        """Generate equivalent x86 assembly for handler."""
        sig = handler.semantic_signature or ""
        # Simple mapping based on handler type
        if handler.handler_type == VMHandlerType.ARITHMETIC:
            if "add" in sig:
                return "add eax, ebx"
            elif "sub" in sig:
                return "sub eax, ebx"
        elif handler.handler_type == VMHandlerType.MEMORY:
            return "mov eax, [ebx]"
        elif handler.handler_type == VMHandlerType.STACK:
            if "push" in sig:
                return "push eax"
            elif "pop" in sig:
                return "pop eax"

        return None

    def _calculate_handler_confidence(self, handler: VMHandler) -> float:
        """Calculate confidence score for handler classification."""
        return calculate_handler_confidence(handler)

    def _analyze_vm_context(self) -> None:
        """Infer the VM's context registers from the dispatcher.

        The observable machinery of a computed-goto dispatcher is two registers:
        the virtual program counter (the base of the opcode fetch) and the opcode
        register (the index of the table dispatch jump). Both are recorded as VM
        registers. Deeper context inference for stack-based VMs (context-pointer
        recovery, spill-slot identification, register-file sizing) is not attempted
        here - vm_stack_address and vm_context_size are left at their defaults
        rather than fabricated for a register-based interpreter that has none.
        """
        arch = self.vm_architecture
        if arch is None:
            return
        registers: list[str] = []
        vpc = self._find_fetch_register(arch.dispatcher_address)
        if vpc is not None:
            registers.append(vpc)
        opcode_register = self._find_dispatch_index_register(arch.dispatcher_address)
        if opcode_register is not None and opcode_register not in registers:
            registers.append(opcode_register)
        arch.vm_registers = sorted(registers)

    def _find_dispatch_index_register(self, dispatcher_addr: int) -> str | None:
        """Return the opcode register: the index of the table dispatch jump."""
        for insn in self.binary.get_function_disasm(dispatcher_addr):
            addr = insn.get("addr")
            if not isinstance(addr, int) or insn.get("type") not in _INDIRECT_JUMP_TYPES:
                continue
            for operand in self._instruction_operands(addr):
                index = operand.get("index")
                if operand.get("type") == "mem" and isinstance(index, str):
                    return index
        return None

    def _locate_vm_bytecode(self) -> None:
        """Locate the VM bytecode region the dispatcher fetches from.

        The virtual program counter (vpc) is the register the opcode fetch - a
        one-byte memory read - dereferences; the bytecode base is the pointer the
        dispatcher materializes into that register (``lea vpc, [bytecode]``). This
        is best-effort: if the vpc or its initializing pointer cannot be observed,
        the field is left at its default rather than guessed.
        """
        arch = self.vm_architecture
        if arch is None:
            return
        vpc = self._find_fetch_register(arch.dispatcher_address)
        if vpc is None:
            return
        bytecode = self._find_pointer_into_register(arch.dispatcher_address, vpc)
        if bytecode is not None and bytecode != arch.handler_table_address:
            arch.bytecode_address = bytecode

    def _instruction_operands(self, addr: int) -> list[dict[str, Any]]:
        """Structured operands of the instruction at ``addr`` (empty on failure)."""
        assert self.binary.r2 is not None
        try:
            analysis = self.binary.r2.cmdj(f"aoj 1 @ {addr}")
        except Exception as e:
            logger.debug(f"Failed to analyze instruction at 0x{addr:x}: {e}")
            return []
        if not analysis:
            return []
        operands = analysis[0].get("opex", {}).get("operands", [])
        return operands if isinstance(operands, list) else []

    def _find_fetch_register(self, dispatcher_addr: int) -> str | None:
        """Return the vpc: the base register the opcode fetch (1-byte read) uses."""
        for insn in self.binary.get_function_disasm(dispatcher_addr):
            addr = insn.get("addr")
            if not isinstance(addr, int):
                continue
            for operand in self._instruction_operands(addr):
                base = operand.get("base")
                if operand.get("type") == "mem" and operand.get("size") == 1 and isinstance(base, str):
                    return base
        return None

    def _find_pointer_into_register(self, dispatcher_addr: int, register: str) -> int | None:
        """Return the address materialized into ``register`` (the bytecode base)."""
        for insn in self.binary.get_function_disasm(dispatcher_addr):
            addr = insn.get("addr")
            if not isinstance(addr, int):
                continue
            operands = self._instruction_operands(addr)
            if not operands or operands[0].get("type") != "reg" or operands[0].get("value") != register:
                continue
            ptr = insn.get("ptr")
            if isinstance(ptr, int) and ptr > 0:
                return ptr
        return None

    def get_handler_statistics(self) -> dict[str, Any]:
        """Get statistics about analyzed handlers."""
        return build_handler_statistics(self.vm_architecture)
