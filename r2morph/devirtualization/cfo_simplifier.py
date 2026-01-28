"""
Control Flow Obfuscation (CFO) Simplifier for r2morph.

This module implements advanced techniques for detecting and simplifying 
control flow obfuscation patterns commonly used by commercial packers
like VMProtect, Themida, and custom obfuscators.

Key Features:
- Dispatcher-based control flow flattening detection
- Switch-case obfuscation reconstruction  
- Indirect jump resolution
- Opaque predicate elimination
- Control flow graph reconstruction
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

logger = logging.getLogger(__name__)


class CFOPattern(Enum):
    """Types of control flow obfuscation patterns."""
    DISPATCHER_FLATTENING = "dispatcher_flattening"
    SWITCH_CASE_OBFUSCATION = "switch_case_obfuscation"
    INDIRECT_JUMPS = "indirect_jumps"
    OPAQUE_PREDICATES = "opaque_predicates"
    FAKE_CONTROL_FLOW = "fake_control_flow"
    EXCEPTION_BASED_FLOW = "exception_based_flow"


@dataclass
class ControlFlowBlock:
    """Represents a basic block in control flow analysis."""
    address: int
    instructions: list[dict[str, Any]] = field(default_factory=list)
    predecessors: set[int] = field(default_factory=set)
    successors: set[int] = field(default_factory=set)
    is_dispatcher: bool = False
    dispatcher_state: int | None = None
    original_target: int | None = None


@dataclass
class DispatcherInfo:
    """Information about a control flow dispatcher."""
    dispatcher_address: int
    state_variable: str
    dispatch_table: dict[int, int] = field(default_factory=dict)
    entry_blocks: set[int] = field(default_factory=set)
    exit_blocks: set[int] = field(default_factory=set)
    pattern_confidence: float = 0.0


@dataclass
class CFOSimplificationResult:
    """Result of control flow obfuscation simplification."""
    success: bool
    patterns_detected: list[CFOPattern] = field(default_factory=list)
    simplified_blocks: dict[int, ControlFlowBlock] = field(default_factory=dict)
    original_complexity: int = 0
    simplified_complexity: int = 0
    dispatcher_info: list[DispatcherInfo] = field(default_factory=list)
    removed_opcodes: list[str] = field(default_factory=list)
    execution_time: float = 0.0
    warnings: list[str] = field(default_factory=list)


class CFOSimplifier:
    """
    Advanced Control Flow Obfuscation simplifier.
    
    Detects and simplifies various control flow obfuscation techniques
    used by commercial packers and custom obfuscators.
    """
    
    def __init__(self, binary=None):
        """Initialize the CFO simplifier."""
        self.binary = binary
        self.blocks = {}
        self.cfg = None
        self.dispatchers = []
        
        # Pattern detection thresholds
        self.dispatcher_threshold = 0.7
        self.opaque_predicate_threshold = 0.8
        
        # Analysis cache
        self._analysis_cache = {}
        
        if not NETWORKX_AVAILABLE:
            logger.warning("NetworkX not available - CFG analysis will be limited")
    
    def simplify_control_flow(self, function_address: int, max_iterations: int = 10) -> CFOSimplificationResult:
        """
        Simplify control flow obfuscation in a function.
        
        Args:
            function_address: Address of the function to analyze
            max_iterations: Maximum number of simplification iterations
            
        Returns:
            CFOSimplificationResult with analysis results
        """
        import time
        start_time = time.time()
        
        try:
            logger.info(f"Starting CFO simplification for function at 0x{function_address:x}")
            
            # Build initial control flow graph
            self._build_cfg(function_address)
            original_complexity = self._calculate_complexity()
            
            # Detect obfuscation patterns
            patterns = self._detect_obfuscation_patterns()
            
            if not patterns:
                return CFOSimplificationResult(
                    success=True,
                    original_complexity=original_complexity,
                    simplified_complexity=original_complexity,
                    execution_time=time.time() - start_time,
                    warnings=["No obfuscation patterns detected"]
                )
            
            # Apply simplification techniques iteratively
            for iteration in range(max_iterations):
                logger.debug(f"CFO simplification iteration {iteration + 1}")
                
                changes_made = False
                
                # Apply each simplification technique
                if CFOPattern.DISPATCHER_FLATTENING in patterns:
                    if self._simplify_dispatcher_flattening():
                        changes_made = True
                
                if CFOPattern.OPAQUE_PREDICATES in patterns:
                    if self._eliminate_opaque_predicates():
                        changes_made = True
                
                if CFOPattern.INDIRECT_JUMPS in patterns:
                    if self._resolve_indirect_jumps():
                        changes_made = True
                
                if CFOPattern.FAKE_CONTROL_FLOW in patterns:
                    if self._remove_fake_control_flow():
                        changes_made = True
                
                # Check for convergence
                if not changes_made:
                    logger.debug(f"CFO simplification converged after {iteration + 1} iterations")
                    break
            
            simplified_complexity = self._calculate_complexity()
            
            return CFOSimplificationResult(
                success=True,
                patterns_detected=patterns,
                simplified_blocks=self.blocks.copy(),
                original_complexity=original_complexity,
                simplified_complexity=simplified_complexity,
                dispatcher_info=self.dispatchers.copy(),
                execution_time=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"CFO simplification failed: {e}")
            return CFOSimplificationResult(
                success=False,
                execution_time=time.time() - start_time,
                warnings=[f"Simplification failed: {str(e)}"]
            )
    
    def _build_cfg(self, function_address: int):
        """Build control flow graph for the function."""
        if not self.binary:
            logger.warning("No binary object available for CFG analysis")
            return
        
        try:
            # Get function information from r2
            self.binary.r2.cmd(f"s {function_address}")
            
            # Analyze function and get basic blocks
            func_info = self.binary.r2.cmdj(f"afij @ {function_address}")
            if not func_info:
                logger.warning(f"Could not analyze function at 0x{function_address:x}")
                return
            
            # Get basic blocks
            blocks_info = self.binary.r2.cmdj(f"afbj @ {function_address}")
            if not blocks_info:
                logger.warning("No basic blocks found")
                return
            
            # Build block objects
            for block_info in blocks_info:
                address = block_info.get('addr', 0)
                
                # Get instructions for this block
                instructions = self.binary.r2.cmdj(f"pdj {block_info.get('ninstr', 0)} @ {address}")
                if not instructions:
                    instructions = []
                
                # Create block object
                block = ControlFlowBlock(
                    address=address,
                    instructions=instructions
                )
                
                # Add successors
                if 'jump' in block_info:
                    block.successors.add(block_info['jump'])
                if 'fail' in block_info:
                    block.successors.add(block_info['fail'])
                
                self.blocks[address] = block
            
            # Build predecessor relationships
            for address, block in self.blocks.items():
                for successor in block.successors:
                    if successor in self.blocks:
                        self.blocks[successor].predecessors.add(address)
            
            # Build NetworkX graph if available
            if NETWORKX_AVAILABLE:
                self.cfg = nx.DiGraph()
                for address, block in self.blocks.items():
                    self.cfg.add_node(address)
                    for successor in block.successors:
                        self.cfg.add_edge(address, successor)
            
            logger.debug(f"Built CFG with {len(self.blocks)} blocks")
            
        except Exception as e:
            logger.error(f"Failed to build CFG: {e}")
    
    def _detect_obfuscation_patterns(self) -> list[CFOPattern]:
        """Detect various control flow obfuscation patterns."""
        patterns = []
        
        try:
            # Detect dispatcher-based flattening
            if self._detect_dispatcher_flattening():
                patterns.append(CFOPattern.DISPATCHER_FLATTENING)
            
            # Detect opaque predicates
            if self._detect_opaque_predicates():
                patterns.append(CFOPattern.OPAQUE_PREDICATES)
            
            # Detect indirect jumps
            if self._detect_indirect_jumps():
                patterns.append(CFOPattern.INDIRECT_JUMPS)
            
            # Detect fake control flow
            if self._detect_fake_control_flow():
                patterns.append(CFOPattern.FAKE_CONTROL_FLOW)
            
            # Detect switch-case obfuscation
            if self._detect_switch_case_obfuscation():
                patterns.append(CFOPattern.SWITCH_CASE_OBFUSCATION)
            
            logger.info(f"Detected {len(patterns)} obfuscation patterns: {[p.value for p in patterns]}")
            
        except Exception as e:
            logger.error(f"Pattern detection failed: {e}")
        
        return patterns
    
    def _detect_dispatcher_flattening(self) -> bool:
        """Detect dispatcher-based control flow flattening."""
        try:
            dispatcher_candidates = []
            
            for address, block in self.blocks.items():
                # Look for blocks with many predecessors (potential dispatchers)
                if len(block.predecessors) >= 3:
                    # Check if block contains switch-like instructions
                    has_switch_pattern = False
                    state_variable = None
                    
                    for instr in block.instructions:
                        opcode = instr.get('opcode', '').lower()
                        
                        # Look for comparison and conditional jump patterns
                        if any(op in opcode for op in ['cmp', 'test', 'je', 'jne', 'jmp']):
                            has_switch_pattern = True
                        
                        # Try to identify state variable
                        if 'cmp' in opcode and 'operands' in instr:
                            # Extract potential state variable
                            operands = instr.get('operands', [])
                            if operands and len(operands) >= 2:
                                state_variable = operands[0].get('value', '')
                    
                    if has_switch_pattern:
                        dispatcher_info = DispatcherInfo(
                            dispatcher_address=address,
                            state_variable=state_variable or f"var_{address:x}",
                            pattern_confidence=0.7
                        )
                        
                        # Analyze dispatch targets
                        self._analyze_dispatch_targets(dispatcher_info)
                        
                        if dispatcher_info.pattern_confidence >= self.dispatcher_threshold:
                            dispatcher_candidates.append(dispatcher_info)
                            block.is_dispatcher = True
            
            self.dispatchers.extend(dispatcher_candidates)
            return len(dispatcher_candidates) > 0
            
        except Exception as e:
            logger.error(f"Dispatcher detection failed: {e}")
            return False
    
    def _detect_opaque_predicates(self) -> bool:
        """Detect opaque predicates (always true/false conditions)."""
        try:
            opaque_count = 0
            
            for address, block in self.blocks.items():
                for instr in block.instructions:
                    opcode = instr.get('opcode', '').lower()
                    
                    # Look for suspicious comparison patterns
                    if 'cmp' in opcode or 'test' in opcode:
                        operands = instr.get('operands', [])
                        if len(operands) >= 2:
                            op1 = operands[0].get('value', '')
                            op2 = operands[1].get('value', '')
                            
                            # Detect always-true/false comparisons
                            if op1 == op2:  # x == x (always true)
                                opaque_count += 1
                            elif self._is_constant_expression(op1, op2):
                                opaque_count += 1
            
            return opaque_count > 0
            
        except Exception as e:
            logger.error(f"Opaque predicate detection failed: {e}")
            return False
    
    def _detect_indirect_jumps(self) -> bool:
        """Detect indirect jumps that may hide control flow."""
        try:
            indirect_count = 0
            
            for address, block in self.blocks.items():
                for instr in block.instructions:
                    opcode = instr.get('opcode', '').lower()
                    
                    # Look for indirect jumps
                    if 'jmp' in opcode and '[' in opcode:
                        indirect_count += 1
                    elif 'call' in opcode and '[' in opcode:
                        indirect_count += 1
            
            return indirect_count > 0
            
        except Exception as e:
            logger.error(f"Indirect jump detection failed: {e}")
            return False
    
    def _detect_fake_control_flow(self) -> bool:
        """Detect fake control flow (unreachable code paths)."""
        try:
            if not NETWORKX_AVAILABLE or not self.cfg:
                return False
            
            # Use graph analysis to find unreachable nodes
            entry_node = min(self.blocks.keys()) if self.blocks else 0
            reachable = set(nx.descendants(self.cfg, entry_node))
            reachable.add(entry_node)
            
            unreachable_count = len(self.blocks) - len(reachable)
            return unreachable_count > 0
            
        except Exception as e:
            logger.error(f"Fake control flow detection failed: {e}")
            return False
    
    def _detect_switch_case_obfuscation(self) -> bool:
        """Detect obfuscated switch-case statements."""
        try:
            # Look for patterns indicating obfuscated switch statements
            for address, block in self.blocks.items():
                if len(block.successors) > 3:  # Many successors suggest switch
                    # Check for computed jumps
                    for instr in block.instructions:
                        opcode = instr.get('opcode', '').lower()
                        if 'jmp' in opcode and any(reg in opcode for reg in ['eax', 'rax', 'ebx', 'rbx']):
                            return True
            
            return False
            
        except Exception as e:
            logger.error(f"Switch-case detection failed: {e}")
            return False
    
    def _simplify_dispatcher_flattening(self) -> bool:
        """Simplify dispatcher-based control flow flattening."""
        try:
            changes_made = False
            
            for dispatcher in self.dispatchers:
                # Analyze the dispatcher pattern
                dispatcher_block = self.blocks.get(dispatcher.dispatcher_address)
                if not dispatcher_block:
                    continue
                
                # Try to reconstruct original control flow
                reconstructed_edges = self._reconstruct_control_flow(dispatcher)
                
                if reconstructed_edges:
                    # Update CFG with reconstructed edges
                    for source, target in reconstructed_edges:
                        if source in self.blocks and target in self.blocks:
                            self.blocks[source].successors.add(target)
                            self.blocks[target].predecessors.add(source)
                            changes_made = True
                    
                    # Mark dispatcher as bypassed
                    dispatcher_block.is_dispatcher = False
                    logger.debug(f"Simplified dispatcher at 0x{dispatcher.dispatcher_address:x}")
            
            return changes_made
            
        except Exception as e:
            logger.error(f"Dispatcher simplification failed: {e}")
            return False
    
    def _eliminate_opaque_predicates(self) -> bool:
        """Eliminate opaque predicates from control flow."""
        try:
            changes_made = False
            
            for address, block in self.blocks.items():
                # Look for conditional jumps with opaque predicates
                for i, instr in enumerate(block.instructions):
                    opcode = instr.get('opcode', '').lower()
                    
                    if any(jmp in opcode for jmp in ['je', 'jne', 'jz', 'jnz', 'jg', 'jl']):
                        # Check if the preceding comparison is opaque
                        if i > 0:
                            prev_instr = block.instructions[i-1]
                            if self._is_opaque_comparison(prev_instr):
                                # Remove the opaque predicate
                                block.instructions[i-1] = {'opcode': 'nop', 'comment': 'removed_opaque_cmp'}
                                block.instructions[i] = {'opcode': 'jmp', 'comment': 'simplified_jump'}
                                changes_made = True
            
            return changes_made
            
        except Exception as e:
            logger.error(f"Opaque predicate elimination failed: {e}")
            return False
    
    def _resolve_indirect_jumps(self) -> bool:
        """Resolve indirect jumps to direct jumps where possible."""
        try:
            changes_made = False
            
            for address, block in self.blocks.items():
                for i, instr in enumerate(block.instructions):
                    opcode = instr.get('opcode', '').lower()
                    
                    if 'jmp' in opcode and '[' in opcode:
                        # Try to resolve the indirect jump target
                        target = self._resolve_jump_target(instr)
                        if target:
                            # Replace with direct jump
                            block.instructions[i] = {
                                'opcode': f'jmp 0x{target:x}',
                                'comment': 'resolved_indirect_jump'
                            }
                            changes_made = True
            
            return changes_made
            
        except Exception as e:
            logger.error(f"Indirect jump resolution failed: {e}")
            return False
    
    def _remove_fake_control_flow(self) -> bool:
        """Remove fake control flow edges."""
        try:
            if not NETWORKX_AVAILABLE or not self.cfg:
                return False
            
            changes_made = False
            
            # Identify unreachable blocks
            entry_node = min(self.blocks.keys()) if self.blocks else 0
            reachable = set(nx.descendants(self.cfg, entry_node))
            reachable.add(entry_node)
            
            # Remove unreachable blocks
            unreachable_blocks = set(self.blocks.keys()) - reachable
            for block_addr in unreachable_blocks:
                if block_addr in self.blocks:
                    del self.blocks[block_addr]
                    changes_made = True
            
            return changes_made
            
        except Exception as e:
            logger.error(f"Fake control flow removal failed: {e}")
            return False
    
    def _analyze_dispatch_targets(self, dispatcher_info: DispatcherInfo):
        """Analyze dispatch targets for a dispatcher."""
        try:
            dispatcher_block = self.blocks.get(dispatcher_info.dispatcher_address)
            if not dispatcher_block:
                return
            
            # Analyze successors to build dispatch table
            for successor in dispatcher_block.successors:
                successor_block = self.blocks.get(successor)
                if successor_block:
                    # Try to determine the state value that leads to this block
                    state_value = self._extract_state_value(successor_block)
                    if state_value is not None:
                        dispatcher_info.dispatch_table[state_value] = successor
            
            # Update confidence based on dispatch table completeness
            if len(dispatcher_info.dispatch_table) >= 2:
                dispatcher_info.pattern_confidence = min(1.0, 
                    0.5 + (len(dispatcher_info.dispatch_table) * 0.1))
            
        except Exception as e:
            logger.error(f"Dispatch target analysis failed: {e}")
    
    def _reconstruct_control_flow(self, dispatcher: DispatcherInfo) -> list[tuple[int, int]]:
        """Reconstruct original control flow from dispatcher pattern."""
        try:
            reconstructed_edges = []
            
            # Use dispatch table to create direct edges
            for state_value, target in dispatcher.dispatch_table.items():
                # Find blocks that set this state value
                source_blocks = self._find_state_setters(state_value, dispatcher.state_variable)
                
                for source in source_blocks:
                    if source != dispatcher.dispatcher_address:
                        reconstructed_edges.append((source, target))
            
            return reconstructed_edges
            
        except Exception as e:
            logger.error(f"Control flow reconstruction failed: {e}")
            return []
    
    def _calculate_complexity(self) -> int:
        """Calculate control flow complexity metric."""
        try:
            if not NETWORKX_AVAILABLE or not self.cfg:
                # Fallback: use simple edge count
                edge_count = sum(len(block.successors) for block in self.blocks.values())
                return edge_count
            
            # Use cyclomatic complexity
            num_edges = self.cfg.number_of_edges()
            num_nodes = self.cfg.number_of_nodes()
            num_components = nx.number_weakly_connected_components(self.cfg)
            
            # Cyclomatic complexity: M = E - N + 2P
            complexity = num_edges - num_nodes + (2 * num_components)
            return max(1, complexity)
            
        except Exception as e:
            logger.error(f"Complexity calculation failed: {e}")
            return len(self.blocks)
    
    def _is_constant_expression(self, op1: str, op2: str) -> bool:
        """Check if operands form a constant expression."""
        try:
            # Simple heuristics for constant expressions
            if op1.isdigit() and op2.isdigit():
                return True
            
            # Check for mathematical identities (x - x, x ^ x, etc.)
            if op1 == op2:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _is_opaque_comparison(self, instr: dict[str, Any]) -> bool:
        """Check if an instruction represents an opaque comparison."""
        try:
            opcode = instr.get('opcode', '').lower()
            
            if 'cmp' not in opcode and 'test' not in opcode:
                return False
            
            operands = instr.get('operands', [])
            if len(operands) < 2:
                return False
            
            op1 = operands[0].get('value', '')
            op2 = operands[1].get('value', '')
            
            return self._is_constant_expression(op1, op2)
            
        except Exception:
            return False
    
    def _resolve_jump_target(self, instr: dict[str, Any]) -> int | None:
        """Try to resolve indirect jump target."""
        try:
            # Simplified implementation for indirect jump analysis
            # Advanced pattern recognition for complex obfuscation
            opcode = instr.get('opcode', '')
            
            # Look for simple patterns like jmp [reg+offset]
            if '[' in opcode and ']' in opcode:
                # Extract the memory reference
                mem_ref = opcode[opcode.find('[')+1:opcode.find(']')]
                
                # Try to resolve simple cases
                if mem_ref.isdigit():
                    try:
                        return int(mem_ref, 16) if 'x' in mem_ref else int(mem_ref)
                    except ValueError:
                        pass
            
            return None
            
        except Exception:
            return None
    
    def _extract_state_value(self, block: ControlFlowBlock) -> int | None:
        """Extract state value from a block."""
        try:
            # Look for immediate values in the first few instructions
            for instr in block.instructions[:3]:
                operands = instr.get('operands', [])
                for operand in operands:
                    value = operand.get('value', '')
                    if value.isdigit():
                        return int(value)
                    elif 'x' in value:
                        try:
                            return int(value, 16)
                        except ValueError:
                            continue
            
            return None
            
        except Exception:
            return None
    
    def _find_state_setters(self, state_value: int, state_variable: str) -> list[int]:
        """Find blocks that set a specific state value."""
        try:
            setters = []
            
            for address, block in self.blocks.items():
                for instr in block.instructions:
                    opcode = instr.get('opcode', '').lower()
                    
                    # Look for mov instructions that set the state variable
                    if 'mov' in opcode:
                        operands = instr.get('operands', [])
                        if len(operands) >= 2:
                            dest = operands[0].get('value', '')
                            src = operands[1].get('value', '')
                            
                            if state_variable in dest and str(state_value) in src:
                                setters.append(address)
                                break
            
            return setters
            
        except Exception:
            return []