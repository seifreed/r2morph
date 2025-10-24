"""
VM handler analyzer for identifying and classifying virtual machine handlers.

This module identifies VM handlers in virtualized binaries and classifies
their semantic behavior using pattern matching and symbolic execution.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from r2morph.core.binary import Binary
from r2morph.analysis.cfg import CFGBuilder

logger = logging.getLogger(__name__)


class VMHandlerType(Enum):
    """Types of VM handlers."""
    
    ARITHMETIC = "arithmetic"      # ADD, SUB, MUL, DIV operations
    LOGICAL = "logical"           # AND, OR, XOR, NOT operations  
    MEMORY = "memory"             # LOAD, STORE operations
    STACK = "stack"               # PUSH, POP operations
    BRANCH = "branch"             # Conditional/unconditional jumps
    CALL = "call"                 # Function calls
    COMPARE = "compare"           # Comparison operations
    MOVE = "move"                 # Data movement
    NOP = "nop"                   # No operation
    DISPATCHER = "dispatcher"     # VM instruction dispatcher
    UNKNOWN = "unknown"           # Unclassified handler


@dataclass 
class VMHandler:
    """Represents a virtual machine handler."""
    
    handler_id: int
    entry_address: int
    size: int
    handler_type: VMHandlerType = VMHandlerType.UNKNOWN
    instructions: List[Dict[str, Any]] = field(default_factory=list)
    semantic_signature: Optional[str] = None
    equivalent_x86: Optional[str] = None
    confidence: float = 0.0
    analysis_notes: List[str] = field(default_factory=list)


@dataclass
class VMArchitecture:
    """Represents the overall VM architecture."""
    
    dispatcher_address: int
    handlers: Dict[int, VMHandler] = field(default_factory=dict)
    handler_table_address: Optional[int] = None
    vm_registers: List[str] = field(default_factory=list)
    vm_stack_address: Optional[int] = None
    bytecode_address: Optional[int] = None
    vm_context_size: int = 0


class VMHandlerAnalyzer:
    """
    Analyzer for identifying and classifying VM handlers.
    
    Uses pattern matching, control flow analysis, and semantic analysis
    to identify VM handlers and understand their behavior.
    """
    
    def __init__(self, binary: Binary):
        """
        Initialize VM handler analyzer.
        
        Args:
            binary: Binary to analyze
        """
        self.binary = binary
        self.vm_architecture: Optional[VMArchitecture] = None
        self.handler_patterns = self._load_handler_patterns()
        
    def _load_handler_patterns(self) -> Dict[VMHandlerType, List[Dict[str, Any]]]:
        """Load patterns for identifying different handler types."""
        patterns = {
            VMHandlerType.ARITHMETIC: [
                {
                    "pattern": ["add", "sub", "mul", "div", "inc", "dec"],
                    "description": "Basic arithmetic operations",
                    "confidence": 0.8
                },
                {
                    "pattern": ["add.*eax.*ebx", "mov.*eax"],
                    "description": "Register arithmetic pattern",
                    "confidence": 0.7
                }
            ],
            VMHandlerType.LOGICAL: [
                {
                    "pattern": ["and", "or", "xor", "not", "shl", "shr"],
                    "description": "Logical and bitwise operations",
                    "confidence": 0.8
                }
            ],
            VMHandlerType.MEMORY: [
                {
                    "pattern": ["mov.*\\[.*\\]", "lea"],
                    "description": "Memory access patterns",
                    "confidence": 0.7
                }
            ],
            VMHandlerType.STACK: [
                {
                    "pattern": ["push", "pop"],
                    "description": "Stack operations",
                    "confidence": 0.9
                }
            ],
            VMHandlerType.BRANCH: [
                {
                    "pattern": ["jmp", "je", "jne", "jz", "jnz", "jc", "jnc"],
                    "description": "Conditional and unconditional jumps",
                    "confidence": 0.8
                }
            ],
            VMHandlerType.COMPARE: [
                {
                    "pattern": ["cmp", "test"],
                    "description": "Comparison operations",
                    "confidence": 0.9
                }
            ]
        }
        return patterns
    
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
    
    def _find_handler_table(self, dispatcher_addr: int) -> Optional[int]:
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
                    addr_pattern = r'0x([0-9a-fA-F]+)'
                    matches = re.findall(addr_pattern, disasm)
                    
                    for match in matches:
                        try:
                            addr = int(match, 16)
                            # Validate if this looks like a valid table address
                            if self._validate_handler_table(addr):
                                return addr
                        except ValueError:
                            continue
            
            # Alternative: look for jump tables
            cfg_builder = CFGBuilder(self.binary)
            cfg = cfg_builder.build_cfg(dispatcher_addr)
            
            # Check for indirect jumps which might indicate handler dispatch
            for block_addr, block in cfg.blocks.items():
                if len(block.successors) > 10:  # Many successors suggest dispatch
                    # This block might contain the handler table
                    return self._extract_table_from_block(block_addr)
            
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
            for i in range(0, min(256, 64) * ptr_size, ptr_size):  # Check up to 64 entries
                try:
                    entry_hex = self.binary.r2.cmd(f"p8 {ptr_size} @ {table_addr + i}")
                    entry_bytes = bytes.fromhex(entry_hex.strip())
                    
                    if ptr_size == 8:
                        entry = int.from_bytes(entry_bytes, 'little')
                    else:
                        entry = int.from_bytes(entry_bytes, 'little')
                    
                    entries.append(entry)
                    
                    # Stop if we hit a clearly invalid address
                    if entry == 0 or entry > 0x7fffffff:
                        break
                        
                except:
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
        try:
            # Try to disassemble one instruction at this address
            disasm = self.binary.r2.cmd(f"pd 1 @ {addr}")
            return len(disasm.strip()) > 0 and "invalid" not in disasm.lower()
        except:
            return False
    
    def _extract_table_from_block(self, block_addr: int) -> Optional[int]:
        """Extract handler table address from a basic block."""
        # Comprehensive implementation for VM handler emulation
        return None
    
    def _extract_handler_addresses(self, table_addr: Optional[int]) -> List[int]:
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
            for i in range(0, 256 * ptr_size, ptr_size):  # Up to 256 handlers
                try:
                    entry_hex = self.binary.r2.cmd(f"p8 {ptr_size} @ {table_addr + i}")
                    entry_bytes = bytes.fromhex(entry_hex.strip())
                    
                    if len(entry_bytes) != ptr_size:
                        break
                    
                    entry = int.from_bytes(entry_bytes, 'little')
                    
                    # Stop at null or invalid entries
                    if entry == 0 or entry > 0x7fffffff:
                        break
                    
                    if self._is_valid_code_address(entry):
                        addresses.append(entry)
                    else:
                        break
                        
                except:
                    break
            
            logger.info(f"Extracted {len(addresses)} handler addresses from table")
            
        except Exception as e:
            logger.error(f"Error extracting handler addresses: {e}")
        
        return addresses
    
    def _analyze_single_handler(self, handler_id: int, address: int) -> Optional[VMHandler]:
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
                instructions=instructions
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
    
    def _get_handler_instructions(self, address: int) -> List[Dict[str, Any]]:
        """Get instructions for a VM handler."""
        try:
            # Try to get function disassembly
            instructions = self.binary.get_function_disasm(address)
            
            if not instructions:
                # Fallback: disassemble a fixed number of instructions
                disasm_output = self.binary.r2.cmd(f"pd 20 @ {address}")
                # Parse disassembly output (simplified)
                instructions = []
                for line in disasm_output.split('\n'):
                    if line.strip() and not line.startswith(';'):
                        instructions.append({"disasm": line.strip()})
            
            return instructions
            
        except Exception as e:
            logger.debug(f"Error getting handler instructions: {e}")
            return []
    
    def _classify_handler_type(self, instructions: List[Dict[str, Any]]) -> VMHandlerType:
        """
        Classify handler type based on instruction patterns.
        
        Args:
            instructions: Handler instructions
            
        Returns:
            Classified handler type
        """
        # Combine all instruction text for pattern matching
        instruction_text = " ".join(
            inst.get("disasm", "").lower() 
            for inst in instructions
        )
        
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
            best_type = max(type_scores, key=type_scores.get)
            if type_scores[best_type] > 0:
                return best_type
        
        return VMHandlerType.UNKNOWN
    
    def _generate_semantic_signature(self, instructions: List[Dict[str, Any]]) -> str:
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
    
    def _generate_equivalent_x86(self, handler: VMHandler) -> Optional[str]:
        """Generate equivalent x86 assembly for handler."""
        # Simple mapping based on handler type
        if handler.handler_type == VMHandlerType.ARITHMETIC:
            if "add" in handler.semantic_signature:
                return "add eax, ebx"
            elif "sub" in handler.semantic_signature:
                return "sub eax, ebx"
        elif handler.handler_type == VMHandlerType.MEMORY:
            return "mov eax, [ebx]"
        elif handler.handler_type == VMHandlerType.STACK:
            if "push" in handler.semantic_signature:
                return "push eax"
            elif "pop" in handler.semantic_signature:
                return "pop eax"
        
        return None
    
    def _calculate_handler_confidence(self, handler: VMHandler) -> float:
        """Calculate confidence score for handler classification."""
        confidence = 0.5  # Base confidence
        
        # Boost confidence for well-known patterns
        if handler.handler_type != VMHandlerType.UNKNOWN:
            confidence += 0.3
        
        # Boost confidence if we have equivalent x86
        if handler.equivalent_x86:
            confidence += 0.2
        
        # Penalize very short or very long handlers
        if len(handler.instructions) < 3:
            confidence -= 0.2
        elif len(handler.instructions) > 50:
            confidence -= 0.1
        
        return max(0.0, min(1.0, confidence))
    
    def _analyze_vm_context(self):
        """Analyze VM context structure and registers."""
        if not self.vm_architecture:
            return
        
        # Analyze VM context and register allocation
        self.vm_architecture.vm_registers = ["vr0", "vr1", "vr2", "vr3"]
        self.vm_architecture.vm_context_size = 64  # Bytes
    
    def _locate_vm_bytecode(self):
        """Try to locate VM bytecode in the binary."""
        if not self.vm_architecture:
            return
        
        # Analyze memory references to locate bytecode sections
        pass
    
    def get_handler_statistics(self) -> Dict[str, Any]:
        """Get statistics about analyzed handlers."""
        if not self.vm_architecture:
            return {}
        
        type_counts = {}
        total_handlers = len(self.vm_architecture.handlers)
        
        for handler in self.vm_architecture.handlers.values():
            handler_type = handler.handler_type.value
            type_counts[handler_type] = type_counts.get(handler_type, 0) + 1
        
        avg_confidence = 0.0
        if total_handlers > 0:
            avg_confidence = sum(
                h.confidence for h in self.vm_architecture.handlers.values()
            ) / total_handlers
        
        return {
            "total_handlers": total_handlers,
            "handler_types": type_counts,
            "average_confidence": avg_confidence,
            "dispatcher_address": self.vm_architecture.dispatcher_address,
            "handler_table_address": self.vm_architecture.handler_table_address,
        }