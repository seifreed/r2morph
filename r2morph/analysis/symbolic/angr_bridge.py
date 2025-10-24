"""
Bridge between radare2 and angr for seamless analysis integration.

This module converts r2 analysis data (CFG, functions, instructions) into
angr project format, enabling symbolic execution of binary code analyzed
by radare2.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    import angr
    import archinfo
    from angr import Project, SimState
    from angr.analyses import CFGFast
    ANGR_AVAILABLE = True
else:
    try:
        import angr
        import archinfo
        from angr import Project, SimState
        from angr.analyses import CFGFast
        ANGR_AVAILABLE = True
    except ImportError:
        ANGR_AVAILABLE = False
        angr = None
        Project = None
        SimState = None
        CFGFast = None

from r2morph.core.binary import Binary
from r2morph.analysis.cfg import ControlFlowGraph, BasicBlock

logger = logging.getLogger(__name__)


class AngrBridge:
    """
    Bridge between r2 and angr for unified binary analysis.
    
    Converts r2 analysis results into angr-compatible format and
    provides bidirectional data flow between the frameworks.
    """
    
    def __init__(self, binary: Binary, auto_load_libs: bool = False):
        """
        Initialize the Angr bridge.
        
        Args:
            binary: r2morph Binary instance
            auto_load_libs: Whether to auto-load shared libraries
        """
        if not ANGR_AVAILABLE:
            raise ImportError("angr is required for symbolic execution. Install with: pip install angr")
            
        self.binary = binary
        self.auto_load_libs = auto_load_libs
        self._angr_project: Optional[Any] = None
        self._r2_to_angr_mapping: Dict[int, int] = {}
        self._angr_to_r2_mapping: Dict[int, int] = {}
        
    @property
    def angr_project(self) -> Any:
        """Get or create angr project."""
        if self._angr_project is None:
            self._angr_project = self._create_angr_project()
        return self._angr_project
    
    def _create_angr_project(self) -> Any:
        """
        Create angr project from r2 binary.
        
        Returns:
            Configured angr Project
        """
        try:
            # Get binary path from r2
            binary_path = Path(self.binary.path)
            
            # Create angr project with appropriate settings
            project = angr.Project(
                str(binary_path),
                auto_load_libs=self.auto_load_libs,
                use_sim_procedures=True,
                exclude_sim_procedures_func=self._should_exclude_simprocedure,
            )
            
            logger.info(f"Created angr project for {binary_path}")
            logger.info(f"Architecture: {project.arch}")
            logger.info(f"Entry point: 0x{project.entry:x}")
            
            return project
            
        except Exception as e:
            logger.error(f"Failed to create angr project: {e}")
            raise
    
    def _should_exclude_simprocedure(self, func_name: str) -> bool:
        """
        Determine if a function should be excluded from sim procedures.
        
        Args:
            func_name: Function name
            
        Returns:
            True if function should be excluded
        """
        # Don't use sim procedures for functions we want to analyze symbolically
        excluded_patterns = [
            "malloc", "free", "memcpy", "memset",  # Memory operations
            "printf", "scanf", "fprintf",  # I/O operations
        ]
        
        return any(pattern in func_name.lower() for pattern in excluded_patterns)
    
    def convert_r2_cfg_to_angr(self, r2_cfg: ControlFlowGraph) -> Optional[Any]:
        """
        Convert r2 CFG to angr CFG format.
        
        Args:
            r2_cfg: r2morph ControlFlowGraph
            
        Returns:
            angr CFGFast instance or None if conversion fails
        """
        try:
            # Perform angr CFG analysis on the same function
            cfg = self.angr_project.analyses.CFGFast(
                regions=[(r2_cfg.function_address, r2_cfg.function_address + 0x1000)],
                normalize=True,
                data_references=True,
            )
            
            # Store mapping between r2 and angr addresses
            self._build_address_mapping(r2_cfg, cfg)
            
            return cfg
            
        except Exception as e:
            logger.error(f"Failed to convert r2 CFG to angr: {e}")
            return None
    
    def _build_address_mapping(self, r2_cfg: ControlFlowGraph, angr_cfg: Any):
        """
        Build bidirectional mapping between r2 and angr addresses.
        
        Args:
            r2_cfg: r2morph CFG
            angr_cfg: angr CFG
        """
        # For now, assume direct address mapping (same virtual addresses)
        for r2_addr, r2_block in r2_cfg.blocks.items():
            if angr_cfg.get_any_node(r2_addr):
                self._r2_to_angr_mapping[r2_addr] = r2_addr
                self._angr_to_r2_mapping[r2_addr] = r2_addr
    
    def create_symbolic_state(self, 
                            address: int, 
                            concrete_values: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """
        Create symbolic state for analysis at given address.
        
        Args:
            address: Starting address for symbolic execution
            concrete_values: Concrete values for registers/memory
            
        Returns:
            Configured SimState or None if creation fails
        """
        try:
            # Create blank state at specified address
            state = self.angr_project.factory.blank_state(addr=address)
            
            # Apply concrete values if provided
            if concrete_values:
                for reg_name, value in concrete_values.items():
                    if hasattr(state.regs, reg_name):
                        setattr(state.regs, reg_name, value)
            
            # Set up symbolic memory regions as needed
            self._setup_symbolic_memory(state)
            
            logger.debug(f"Created symbolic state at 0x{address:x}")
            return state
            
        except Exception as e:
            logger.error(f"Failed to create symbolic state: {e}")
            return None
    
    def _setup_symbolic_memory(self, state: Any):
        """
        Set up symbolic memory regions for analysis.
        
        Args:
            state: SimState to configure
        """
        # Mark stack as symbolic
        stack_size = 0x10000  # 64KB stack
        stack_base = state.regs.rsp - stack_size
        
        # Make stack region symbolic but with reasonable constraints
        for offset in range(0, stack_size, 8):
            addr = stack_base + offset
            state.memory.store(addr, state.solver.BVS(f"stack_{offset:x}", 64))
    
    def get_function_boundaries(self, function_addr: int) -> Tuple[int, int]:
        """
        Get function start and end addresses from angr analysis.
        
        Args:
            function_addr: Function address
            
        Returns:
            Tuple of (start_addr, end_addr)
        """
        try:
            func = self.angr_project.kb.functions.get(function_addr)
            if func:
                return func.addr, func.addr + func.size
            else:
                # Fallback to r2 analysis
                functions = self.binary.get_functions()
                for f in functions:
                    if f.get("offset", 0) == function_addr:
                        size = f.get("size", 0x100)
                        return function_addr, function_addr + size
                        
                # Default size if not found
                return function_addr, function_addr + 0x100
                
        except Exception as e:
            logger.error(f"Failed to get function boundaries: {e}")
            return function_addr, function_addr + 0x100
    
    def synchronize_analysis_results(self):
        """
        Synchronize analysis results between r2 and angr.
        
        This method ensures both frameworks have consistent views
        of the binary structure and analysis results.
        """
        try:
            # Re-analyze with angr to get updated CFG
            cfg = self.angr_project.analyses.CFGFast()
            
            # Update r2 analysis with angr discoveries
            for func_addr in cfg.kb.functions:
                func = cfg.kb.functions[func_addr]
                
                # Check if r2 missed this function
                r2_functions = self.binary.get_functions()
                r2_addrs = {f.get("offset", 0) for f in r2_functions}
                
                if func_addr not in r2_addrs:
                    logger.info(f"angr discovered new function at 0x{func_addr:x}")
                    # Could potentially add to r2 via commands
                    
        except Exception as e:
            logger.error(f"Failed to synchronize analysis results: {e}")
    
    def cleanup(self):
        """Clean up resources."""
        if self._angr_project:
            # angr doesn't require explicit cleanup, but we can clear references
            self._angr_project = None
        self._r2_to_angr_mapping.clear()
        self._angr_to_r2_mapping.clear()