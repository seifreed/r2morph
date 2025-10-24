"""
Enhanced obfuscation detector for identifying packer types and obfuscation techniques.

This module extends the existing detection capabilities to specifically identify:
- VMProtect, Themida, and other commercial packers
- Control flow obfuscation patterns
- Mixed Boolean Arithmetic (MBA) expressions
- Virtual machine-based obfuscation
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from r2morph.core.binary import Binary
from r2morph.detection.entropy_analyzer import EntropyAnalyzer
from r2morph.analysis.cfg import CFGBuilder

logger = logging.getLogger(__name__)


class PackerType(Enum):
    """Known packer and obfuscator types."""
    
    # Commercial VM-based packers
    VMPROTECT = "vmprotect"
    THEMIDA = "themida"
    WINLICENSE = "winlicense"
    ENIGMA = "enigma"
    OBSIDIUM = "obsidium"
    SAFENGINE = "safengine"
    VPROTECT = "vprotect"
    
    # Traditional packers
    UPX = "upx"
    ASPACK = "aspack"
    PECOMPACT = "pecompact"
    MPRESS = "mpress"
    PACKMAN = "packman"
    NSPACK = "nspack"
    RLPACK = "rlpack"
    PESPIN = "pespin"
    
    # Protection systems
    ASPROTECT = "asprotect"
    ARMADILLO = "armadillo"
    EXECRYPTOR = "execryptor"
    PKLITE = "pklite"
    WWPACK = "wwpack"
    
    # Custom/Unknown
    CUSTOM_VM = "custom_vm"
    CUSTOM_PACKER = "custom_packer"
    METAMORPHIC = "metamorphic"
    UNKNOWN = "unknown"
    NONE = "none"


class ObfuscationType(Enum):
    """Types of obfuscation techniques."""
    
    CONTROL_FLOW_FLATTENING = "cff"
    OPAQUE_PREDICATES = "opaque_predicates"
    MIXED_BOOLEAN_ARITHMETIC = "mba"
    INSTRUCTION_SUBSTITUTION = "inst_substitution"
    VIRTUALIZATION = "virtualization"
    PACKING = "packing"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    STRING_ENCRYPTION = "string_encryption"
    IMPORT_HIDING = "import_hiding"


@dataclass
class PackerSignature:
    """Signature for identifying specific packers."""
    
    name: str
    packer_type: PackerType
    entry_patterns: List[bytes] = field(default_factory=list)
    section_names: List[str] = field(default_factory=list)
    import_patterns: List[str] = field(default_factory=list)
    string_patterns: List[str] = field(default_factory=list)
    entropy_threshold: float = 7.0
    confidence_threshold: float = 0.7


@dataclass
class ObfuscationAnalysisResult:
    """Result of obfuscation analysis."""
    
    packer_detected: PackerType = PackerType.NONE
    obfuscation_techniques: List[ObfuscationType] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    vm_detected: bool = False
    vm_handler_count: int = 0
    mba_expressions_found: int = 0
    opaque_predicates_found: int = 0
    analysis_details: Dict[str, Any] = field(default_factory=dict)
    requires_devirtualization: bool = False
    requires_dynamic_analysis: bool = False


class ObfuscationDetector:
    """
    Advanced obfuscation and packer detection.
    
    Identifies various obfuscation techniques and commercial packers
    to guide the appropriate deobfuscation strategy.
    """
    
    def __init__(self):
        """Initialize obfuscation detector."""
        self.packer_signatures = self._load_packer_signatures()
        self.entropy_analyzer = EntropyAnalyzer()
    
    def _load_packer_signatures(self) -> List[PackerSignature]:
        """Load known packer signatures."""
        signatures = []
        
        # VMProtect signatures (multiple versions)
        signatures.append(PackerSignature(
            name="VMProtect 3.x",
            packer_type=PackerType.VMPROTECT,
            entry_patterns=[
                b'\x68\x00\x00\x00\x00\xe8\x00\x00\x00\x00',  # push 0; call
                b'\xeb\x10\x53\x51\x52\x56\x57\x55',  # VMProtect entry stub
                b'\x60\xbe\x00\x00\x41\x00\x8d\xbe\x00\xb0\xff\xff',  # VMProtect 2.x
            ],
            section_names=[".vmp0", ".vmp1", ".vmp2", ".vmp"],
            string_patterns=["VMProtect", "www.vmprotect.com", "PolyTech"],
            entropy_threshold=7.5,
            confidence_threshold=0.8
        ))
        
        # Themida/WinLicense signatures
        signatures.append(PackerSignature(
            name="Themida/WinLicense",
            packer_type=PackerType.THEMIDA,
            entry_patterns=[
                b'\x8b\xff\x55\x8b\xec\x6a\xff\x68',  # Themida entry
                b'\x50\x53\x51\x52\x56\x57\x55\x8b',  # WinLicense entry
                b'\xb8\x00\x00\x00\x00\x60\x0f\xc8',  # Themida 1.x
                b'\x55\x8b\xec\x83\xec\x0c\x53\x56',  # WinLicense 2.x
            ],
            section_names=[".themida", ".winlice", ".tls", ".oreans"],
            import_patterns=["Themida", "WinLicense", "Oreans"],
            string_patterns=["Themida", "Oreans", "WinLicense", "www.oreans.com"],
            entropy_threshold=7.2,
            confidence_threshold=0.75
        ))
        
        # Enigma Protector signatures
        signatures.append(PackerSignature(
            name="Enigma Protector",
            packer_type=PackerType.ENIGMA,
            entry_patterns=[
                b'\x60\xe8\x00\x00\x00\x00\x5d\x50\x51\x52',  # Enigma entry
                b'\xeb\x03\x5d\xeb\x05\xe8\xf8\xff\xff\xff',  # Enigma variant
            ],
            section_names=[".enigma1", ".enigma2", ".eng"],
            string_patterns=["Enigma", "The Enigma Protector"],
            entropy_threshold=7.0,
            confidence_threshold=0.8
        ))
        
        # UPX signatures (multiple versions)
        signatures.append(PackerSignature(
            name="UPX",
            packer_type=PackerType.UPX,
            entry_patterns=[
                b'\x60\xbe\x00\x10\x40\x00\x8d\xbe\x00\xf0\xff\xff',  # UPX 0.xx
                b'\x83\x7c\x24\x08\x01\x0f\x85\x95\x01\x00\x00',  # UPX 1.xx
                b'\x60\xbe\x00\x00\x41\x00\x8d\xbe\x00\xb0\xff\xff',  # UPX 2.xx
            ],
            section_names=["UPX0", "UPX1", "UPX!", ".upx0", ".upx1"],
            string_patterns=["UPX!", "$Id: UPX", "upx394w"],
            entropy_threshold=6.5,
            confidence_threshold=0.9
        ))
        
        # ASPack signatures
        signatures.append(PackerSignature(
            name="ASPack",
            packer_type=PackerType.ASPACK,
            entry_patterns=[
                b'\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04\x5d\x45\x55',  # ASPack 1.x
                b'\x60\xe8\x00\x00\x00\x00\x5d\x81\xed\x96\x78\x43\x00',  # ASPack 2.x
            ],
            section_names=[".aspack", ".adata"],
            string_patterns=["ASPack", "www.aspack.com"],
            entropy_threshold=6.8,
            confidence_threshold=0.85
        ))
        
        # PECompact signatures
        signatures.append(PackerSignature(
            name="PECompact",
            packer_type=PackerType.PECOMPACT,
            entry_patterns=[
                b'\xeb\x06\x68\x00\x00\x00\x00\xc3\x9c\x60\x8b\x74',  # PECompact 1.x
                b'\x8b\x04\x24\x01\x05\x8b\x1c\x24\x01\x1d',  # PECompact 2.x
            ],
            section_names=[".pec1", ".pec2", ".pec"],
            string_patterns=["PECompact2", "Bitsum LLC"],
            entropy_threshold=7.1,
            confidence_threshold=0.8
        ))
        
        # MPRESS signatures
        signatures.append(PackerSignature(
            name="MPRESS",
            packer_type=PackerType.MPRESS,
            entry_patterns=[
                b'\x60\xe8\x00\x00\x00\x00\x58\x05\x5a\x0a\x00\x00',  # MPRESS 1.x
                b'\x60\xe8\x00\x00\x00\x00\x58\x05\x4a\x0a\x00\x00',  # MPRESS 2.x
            ],
            section_names=[".mpress1", ".mpress2"],
            string_patterns=["MPRESS", "mpress"],
            entropy_threshold=6.9,
            confidence_threshold=0.8
        ))
        
        # ASProtect signatures
        signatures.append(PackerSignature(
            name="ASProtect",
            packer_type=PackerType.ASPROTECT,
            entry_patterns=[
                b'\x68\x01\x00\x00\x00\xe8\x01\x00\x00\x00\xc3\xc3',  # ASProtect 1.x
                b'\x90\x60\xe8\x03\x00\x00\x00\xe9\xeb\x04\x5d\x45',  # ASProtect 2.x
            ],
            section_names=[".aspr", ".asprotect"],
            string_patterns=["ASProtect", "www.aspack.com"],
            entropy_threshold=7.3,
            confidence_threshold=0.75
        ))
        
        # Obsidium signatures
        signatures.append(PackerSignature(
            name="Obsidium",
            packer_type=PackerType.OBSIDIUM,
            entry_patterns=[
                b'\xeb\x02\xe8\x25\xeb\x03\xe9\xeb\x04\x40\xeb\x08',  # Obsidium 1.x
                b'\xeb\x01\x90\xeb\x02\xeb\x01\xeb\x05\xe8\x01\x00',  # Obsidium 2.x
            ],
            section_names=[".obsidium", ".obfus"],
            string_patterns=["Obsidium", "www.obsidium.de"],
            entropy_threshold=7.4,
            confidence_threshold=0.8
        ))
        
        # Armadillo signatures
        signatures.append(PackerSignature(
            name="Armadillo",
            packer_type=PackerType.ARMADILLO,
            entry_patterns=[
                b'\x55\x8b\xec\x6a\xff\x68\x00\x00\x00\x00\x68',  # Armadillo entry
            ],
            section_names=[".arma", ".armadill"],
            string_patterns=["Armadillo", "Silicon Realms"],
            entropy_threshold=6.7,
            confidence_threshold=0.75
        ))
        
        # SafeEngine signatures
        signatures.append(PackerSignature(
            name="SafeEngine",
            packer_type=PackerType.SAFENGINE,
            entry_patterns=[
                b'\x60\xe8\x00\x00\x00\x00\x5d\x50\x51\x52\x53',  # SafeEngine entry
            ],
            section_names=[".seau", ".seau1", ".seau2"],
            string_patterns=["SafeEngine"],
            entropy_threshold=7.2,
            confidence_threshold=0.8
        ))
        
        # PESpin signatures
        signatures.append(PackerSignature(
            name="PESpin",
            packer_type=PackerType.PESPIN,
            entry_patterns=[
                b'\xeb\x01\x68\x60\xe8\x00\x00\x00\x00\x8b\x1c\x24',  # PESpin 1.x
            ],
            section_names=[".pespin"],
            string_patterns=["PESpin", "Cyberbob"],
            entropy_threshold=6.8,
            confidence_threshold=0.8
        ))
        
        # Metamorphic engine detection
        signatures.append(PackerSignature(
            name="Metamorphic Engine",
            packer_type=PackerType.METAMORPHIC,
            entry_patterns=[
                # Generic metamorphic patterns - highly variable
                b'\x90\x90\x90\x90\xeb\x??',  # NOPs + variable jump
                b'\x83\xc0\x00\x83\xe8\x00',  # Dead arithmetic
            ],
            section_names=[".meta", ".morph", ".poly"],
            string_patterns=["metamorph", "polymorphic"],
            entropy_threshold=5.5,  # Lower threshold for metamorphic
            confidence_threshold=0.6
        ))
        
        return signatures
    
    def analyze_binary(self, binary: Binary) -> ObfuscationAnalysisResult:
        """
        Perform comprehensive obfuscation analysis.
        
        Args:
            binary: Binary to analyze
            
        Returns:
            Complete obfuscation analysis result
        """
        logger.info("Starting comprehensive obfuscation analysis")
        
        result = ObfuscationAnalysisResult()
        
        # Ensure binary is analyzed
        if not binary.is_analyzed():
            binary.analyze()
        
        # 1. Packer detection
        result.packer_detected = self._detect_packer(binary)
        
        # 2. Entropy analysis
        entropy_result = self.entropy_analyzer.analyze_file(Path(binary.path))
        result.analysis_details["entropy"] = entropy_result
        
        # 3. Control flow analysis
        cff_detected = self._detect_control_flow_flattening(binary)
        if cff_detected:
            result.obfuscation_techniques.append(ObfuscationType.CONTROL_FLOW_FLATTENING)
            result.confidence_scores["control_flow_flattening"] = cff_detected
        
        # 4. VM detection
        vm_result = self._detect_virtualization(binary)
        result.vm_detected = vm_result["detected"]
        result.vm_handler_count = vm_result["handler_count"]
        if result.vm_detected:
            result.obfuscation_techniques.append(ObfuscationType.VIRTUALIZATION)
            result.confidence_scores["virtualization"] = vm_result["confidence"]
        
        # 5. MBA detection
        mba_count = self._detect_mba_patterns(binary)
        result.mba_expressions_found = mba_count
        if mba_count > 0:
            result.obfuscation_techniques.append(ObfuscationType.MIXED_BOOLEAN_ARITHMETIC)
            result.confidence_scores["mba"] = min(1.0, mba_count / 10.0)
        
        # 6. Opaque predicate detection
        opaque_count = self._detect_opaque_predicates(binary)
        result.opaque_predicates_found = opaque_count
        if opaque_count > 0:
            result.obfuscation_techniques.append(ObfuscationType.OPAQUE_PREDICATES)
            result.confidence_scores["opaque_predicates"] = min(1.0, opaque_count / 5.0)
        
        # 7. Anti-analysis detection
        anti_debug = self._detect_anti_debug(binary)
        anti_vm = self._detect_anti_vm(binary)
        
        if anti_debug:
            result.obfuscation_techniques.append(ObfuscationType.ANTI_DEBUG)
            result.confidence_scores["anti_debug"] = anti_debug
        
        if anti_vm:
            result.obfuscation_techniques.append(ObfuscationType.ANTI_VM)
            result.confidence_scores["anti_vm"] = anti_vm
        
        # 8. Determine analysis requirements
        result.requires_devirtualization = (
            result.vm_detected or 
            result.packer_detected in [PackerType.VMPROTECT, PackerType.THEMIDA]
        )
        
        result.requires_dynamic_analysis = (
            result.packer_detected != PackerType.NONE or
            entropy_result.is_packed or
            anti_debug > 0.5 or
            anti_vm > 0.5
        )
        
        logger.info(f"Obfuscation analysis complete: {len(result.obfuscation_techniques)} techniques detected")
        return result
    
    def _detect_packer(self, binary: Binary) -> PackerType:
        """
        Detect specific packer type using signatures.
        
        Args:
            binary: Binary to analyze
            
        Returns:
            Detected packer type
        """
        logger.debug("Detecting packer type")
        
        best_match = PackerType.NONE
        best_confidence = 0.0
        
        try:
            # Get binary information
            sections = binary.get_sections()
            entry_point = binary.info.get("bin", {}).get("baddr", 0)
            
            # Read entry point bytes
            entry_bytes = b""
            try:
                entry_hex = binary.r2.cmd(f"p8 32 @ {entry_point}")
                entry_bytes = bytes.fromhex(entry_hex.strip())
            except:
                pass
            
            # Check each signature
            for signature in self.packer_signatures:
                confidence = self._calculate_signature_confidence(
                    signature, sections, entry_bytes, binary
                )
                
                if confidence > best_confidence and confidence >= signature.confidence_threshold:
                    best_confidence = confidence
                    best_match = signature.packer_type
            
            if best_match != PackerType.NONE:
                logger.info(f"Detected packer: {best_match.value} (confidence: {best_confidence:.2f})")
            
        except Exception as e:
            logger.error(f"Error detecting packer: {e}")
        
        return best_match
    
    def _calculate_signature_confidence(self, 
                                      signature: PackerSignature,
                                      sections: List[Dict[str, Any]],
                                      entry_bytes: bytes,
                                      binary: Binary) -> float:
        """Calculate confidence score for a packer signature."""
        confidence = 0.0
        total_checks = 0
        
        # Check section names
        if signature.section_names:
            section_names = [s.get("name", "") for s in sections]
            for sig_section in signature.section_names:
                total_checks += 1
                if any(sig_section in name for name in section_names):
                    confidence += 1.0
        
        # Check entry point patterns
        if signature.entry_patterns and entry_bytes:
            for pattern in signature.entry_patterns:
                total_checks += 1
                if pattern in entry_bytes:
                    confidence += 1.0
        
        # Check strings
        if signature.string_patterns:
            try:
                strings_output = binary.r2.cmd("izz")
                for pattern in signature.string_patterns:
                    total_checks += 1
                    if pattern.lower() in strings_output.lower():
                        confidence += 1.0
            except:
                pass
        
        # Check entropy
        entropy_result = self.entropy_analyzer.analyze_file(Path(binary.path))
        if entropy_result.overall_entropy >= signature.entropy_threshold:
            total_checks += 1
            confidence += 1.0
        
        return confidence / max(total_checks, 1)
    
    def _detect_control_flow_flattening(self, binary: Binary) -> float:
        """
        Detect control flow flattening obfuscation.
        
        Args:
            binary: Binary to analyze
            
        Returns:
            Confidence score for CFF detection
        """
        try:
            functions = binary.get_functions()
            if not functions:
                return 0.0
            
            cff_indicators = 0
            total_functions = 0
            
            for func in functions[:10]:  # Check first 10 functions
                func_addr = func.get("offset", 0)
                if func_addr == 0:
                    continue
                
                total_functions += 1
                
                # Get basic blocks for this function
                try:
                    blocks = binary.get_basic_blocks(func_addr)
                    if len(blocks) > 20:  # Many basic blocks might indicate flattening
                        
                        # Check for dispatcher pattern (switch-like structure)
                        dispatcher_found = self._check_dispatcher_pattern(binary, blocks)
                        if dispatcher_found:
                            cff_indicators += 1
                            
                except Exception:
                    continue
            
            if total_functions == 0:
                return 0.0
            
            return cff_indicators / total_functions
            
        except Exception as e:
            logger.debug(f"Error detecting control flow flattening: {e}")
            return 0.0
    
    def _check_dispatcher_pattern(self, binary: Binary, blocks: List[Dict[str, Any]]) -> bool:
        """Check for control flow dispatcher pattern."""
        try:
            # Look for blocks with many successors (dispatcher characteristic)
            for block in blocks:
                block_addr = block.get("addr", 0)
                if block_addr == 0:
                    continue
                
                # Get instructions in this block
                instructions = binary.get_function_disasm(block_addr)
                
                # Look for switch/jump table patterns
                for inst in instructions:
                    disasm = inst.get("disasm", "").lower()
                    if ("jmp" in disasm and "[" in disasm) or "switch" in disasm:
                        return True
            
            return False
            
        except Exception:
            return False
    
    def _detect_virtualization(self, binary: Binary) -> Dict[str, Any]:
        """
        Detect virtual machine-based obfuscation.
        
        Args:
            binary: Binary to analyze
            
        Returns:
            VM detection result with confidence and handler count
        """
        result = {
            "detected": False,
            "confidence": 0.0,
            "handler_count": 0,
            "indicators": []
        }
        
        try:
            functions = binary.get_functions()
            vm_indicators = 0
            total_functions = len(functions)
            
            if total_functions == 0:
                return result
            
            # Look for VM characteristics
            for func in functions[:20]:  # Check first 20 functions
                func_addr = func.get("offset", 0)
                if func_addr == 0:
                    continue
                
                try:
                    instructions = binary.get_function_disasm(func_addr)
                    
                    # VM indicator patterns
                    indirect_jumps = 0
                    table_accesses = 0
                    
                    for inst in instructions:
                        disasm = inst.get("disasm", "").lower()
                        
                        # Indirect jumps through registers/memory
                        if "jmp" in disasm and any(reg in disasm for reg in ["eax", "ebx", "ecx", "edx", "rax", "rbx"]):
                            indirect_jumps += 1
                        
                        # Memory table accesses
                        if "mov" in disasm and "[" in disasm and "+" in disasm:
                            table_accesses += 1
                    
                    # High ratio of indirect jumps suggests VM
                    if len(instructions) > 0:
                        indirect_ratio = indirect_jumps / len(instructions)
                        if indirect_ratio > 0.1:  # More than 10% indirect jumps
                            vm_indicators += 1
                            result["indicators"].append(f"High indirect jump ratio in function at 0x{func_addr:x}")
                
                except Exception:
                    continue
            
            # Calculate confidence
            if total_functions > 0:
                vm_ratio = vm_indicators / min(total_functions, 20)
                result["confidence"] = vm_ratio
                result["detected"] = vm_ratio > 0.3  # 30% threshold
                result["handler_count"] = vm_indicators
            
        except Exception as e:
            logger.debug(f"Error detecting virtualization: {e}")
        
        return result
    
    def _detect_mba_patterns(self, binary: Binary) -> int:
        """
        Detect Mixed Boolean Arithmetic expressions.
        
        Args:
            binary: Binary to analyze
            
        Returns:
            Number of MBA patterns found
        """
        mba_count = 0
        
        try:
            functions = binary.get_functions()
            
            for func in functions[:10]:  # Check first 10 functions
                func_addr = func.get("offset", 0)
                if func_addr == 0:
                    continue
                
                try:
                    instructions = binary.get_function_disasm(func_addr)
                    
                    # Look for MBA patterns: complex arithmetic with boolean operations
                    bool_ops = 0
                    arith_ops = 0
                    
                    for inst in instructions:
                        disasm = inst.get("disasm", "").lower()
                        
                        if any(op in disasm for op in ["and", "or", "xor", "not"]):
                            bool_ops += 1
                        
                        if any(op in disasm for op in ["add", "sub", "mul", "imul"]):
                            arith_ops += 1
                    
                    # MBA typically has high mix of boolean and arithmetic operations
                    if bool_ops > 5 and arith_ops > 5 and len(instructions) > 0:
                        mix_ratio = (bool_ops + arith_ops) / len(instructions)
                        if mix_ratio > 0.4:  # More than 40% boolean/arithmetic mix
                            mba_count += 1
                
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"Error detecting MBA patterns: {e}")
        
        return mba_count
    
    def _detect_opaque_predicates(self, binary: Binary) -> int:
        """
        Detect opaque predicates (always true/false conditions).
        
        Args:
            binary: Binary to analyze
            
        Returns:
            Number of potential opaque predicates found
        """
        opaque_count = 0
        
        try:
            functions = binary.get_functions()
            
            for func in functions[:10]:
                func_addr = func.get("offset", 0)
                if func_addr == 0:
                    continue
                
                try:
                    instructions = binary.get_function_disasm(func_addr)
                    
                    # Look for suspicious conditional patterns
                    for i, inst in enumerate(instructions):
                        disasm = inst.get("disasm", "").lower()
                        
                        # Look for comparisons followed by predictable branches
                        if "cmp" in disasm and i + 1 < len(instructions):
                            next_inst = instructions[i + 1].get("disasm", "").lower()
                            
                            # Check for obvious always-true/false conditions
                            if "cmp" in disasm:
                                # Simple heuristic: same register compared with itself
                                words = disasm.split()
                                if len(words) >= 3:
                                    operands = words[1].replace(",", "").split()
                                    if len(operands) >= 2 and operands[0] == operands[1]:
                                        opaque_count += 1
                
                except Exception:
                    continue
        
        except Exception as e:
            logger.debug(f"Error detecting opaque predicates: {e}")
        
        return opaque_count
    
    def _detect_anti_debug(self, binary: Binary) -> float:
        """
        Detect anti-debugging techniques.
        
        Args:
            binary: Binary to analyze
            
        Returns:
            Confidence score for anti-debug detection
        """
        confidence = 0.0
        
        try:
            # Check for anti-debug API calls
            strings_output = binary.r2.cmd("izz")
            
            anti_debug_apis = [
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent", 
                "NtQueryInformationProcess",
                "OutputDebugString",
                "GetTickCount",
                "QueryPerformanceCounter"
            ]
            
            found_apis = 0
            for api in anti_debug_apis:
                if api in strings_output:
                    found_apis += 1
            
            confidence = min(1.0, found_apis / len(anti_debug_apis))
            
        except Exception as e:
            logger.debug(f"Error detecting anti-debug: {e}")
        
        return confidence
    
    def _detect_anti_vm(self, binary: Binary) -> float:
        """
        Detect anti-VM techniques.
        
        Args:
            binary: Binary to analyze
            
        Returns:
            Confidence score for anti-VM detection
        """
        confidence = 0.0
        
        try:
            strings_output = binary.r2.cmd("izz")
            
            vm_artifacts = [
                "vmware", "virtualbox", "vbox", "qemu", "xen",
                "sandboxie", "wine", "bochs", "parallels",
                "vboxservice", "vmtools", "vmmouse"
            ]
            
            found_artifacts = 0
            for artifact in vm_artifacts:
                if artifact.lower() in strings_output.lower():
                    found_artifacts += 1
            
            confidence = min(1.0, found_artifacts / len(vm_artifacts) * 2)  # Scale up
            
        except Exception as e:
            logger.debug(f"Error detecting anti-VM: {e}")
        
        return confidence
    
    def detect_custom_virtualizer(self, binary: Binary) -> Dict[str, Any]:
        """
        Detect custom virtualization engines.
        
        Args:
            binary: Binary to analyze
            
        Returns:
            Dictionary with detection results
        """
        result = {
            "detected": False,
            "confidence": 0.0,
            "indicators": [],
            "vm_type": "unknown"
        }
        
        try:
            # Look for VM-specific patterns
            patterns = {
                "register_based": [
                    b'\x8b\x45\xfc',  # mov eax, [ebp-4] - stack access
                    b'\x89\x45\xfc',  # mov [ebp-4], eax - stack store
                ],
                "stack_based": [
                    b'\x58\x59\x5a\x5b',  # pop sequence
                    b'\x50\x51\x52\x53',  # push sequence
                ],
                "bytecode_handler": [
                    b'\xfe\xc0',      # inc al - bytecode increment
                    b'\x30\xc0',      # xor al, al - bytecode reset
                ]
            }
            
            # Check for each pattern type
            for vm_type, type_patterns in patterns.items():
                pattern_count = 0
                
                for pattern in type_patterns:
                    cmd = f'/x {pattern.hex()}'
                    matches = binary.r2.cmd(cmd)
                    if matches:
                        pattern_count += len(matches.strip().split('\n')) if matches.strip() else 0
                
                if pattern_count > 10:  # Threshold for pattern detection
                    result["detected"] = True
                    result["vm_type"] = vm_type
                    result["confidence"] = min(1.0, pattern_count / 50.0)
                    result["indicators"].append(f"Found {pattern_count} {vm_type} VM patterns")
                    break
            
            # Additional heuristics
            if not result["detected"]:
                # Check for computed jump tables
                jump_table_patterns = [
                    b'\xff\x24\x85',  # jmp [table + reg*4]
                    b'\xff\x24\x95',  # jmp [table + reg*4] variant
                ]
                
                for pattern in jump_table_patterns:
                    cmd = f'/x {pattern.hex()}'
                    matches = binary.r2.cmd(cmd)
                    if matches and matches.strip():
                        result["detected"] = True
                        result["vm_type"] = "jump_table"
                        result["confidence"] = 0.7
                        result["indicators"].append("Found computed jump table patterns")
                        break
            
        except Exception as e:
            logger.error(f"Custom virtualizer detection failed: {e}")
        
        return result
    
    def detect_code_packing_layers(self, binary: Binary) -> Dict[str, Any]:
        """
        Detect multiple packing layers.
        
        Args:
            binary: Binary to analyze
            
        Returns:
            Dictionary with layer analysis
        """
        result = {
            "layers_detected": 0,
            "packers": [],
            "confidence": 0.0,
            "requires_unpacking": False
        }
        
        try:
            # Analyze entropy across sections
            sections = binary.get_sections()
            high_entropy_sections = []
            
            for section in sections:
                if section.get("size", 0) > 0:
                    # Get section data and calculate entropy
                    addr = section.get("vaddr", 0)
                    size = min(section.get("size", 0), 1024)  # Limit for performance
                    
                    try:
                        data_hex = binary.r2.cmd(f"p8 {size} @ {addr}")
                        if data_hex and data_hex.strip():
                            data = bytes.fromhex(data_hex.strip())
                            entropy = self._calculate_entropy(data)
                            
                            if entropy > 7.0:  # High entropy threshold
                                high_entropy_sections.append({
                                    "name": section.get("name", ""),
                                    "entropy": entropy,
                                    "size": size
                                })
                    except Exception:
                        continue
            
            # Multiple high-entropy sections suggest layered packing
            if len(high_entropy_sections) > 1:
                result["layers_detected"] = len(high_entropy_sections)
                result["requires_unpacking"] = True
                result["confidence"] = min(1.0, len(high_entropy_sections) / 5.0)
            
            # Check for nested packer signatures
            for signature in self.packer_signatures:
                sections_list = binary.get_sections()
                entry_bytes = self._get_entry_bytes(binary)
                
                confidence = self._calculate_signature_confidence(
                    signature, sections_list, entry_bytes, binary
                )
                
                if confidence > 0.5:
                    result["packers"].append({
                        "name": signature.name,
                        "type": signature.packer_type.value,
                        "confidence": confidence
                    })
            
            # If multiple packers detected, likely layered
            if len(result["packers"]) > 1:
                result["layers_detected"] = max(result["layers_detected"], len(result["packers"]))
                result["requires_unpacking"] = True
            
        except Exception as e:
            logger.error(f"Layer detection failed: {e}")
        
        return result
    
    def detect_metamorphic_engine(self, binary: Binary) -> Dict[str, Any]:
        """
        Detect metamorphic code generation.
        
        Args:
            binary: Binary to analyze
            
        Returns:
            Dictionary with metamorphic analysis
        """
        result = {
            "detected": False,
            "confidence": 0.0,
            "indicators": [],
            "polymorphic_ratio": 0.0
        }
        
        try:
            functions = binary.get_functions()
            total_functions = len(functions)
            polymorphic_functions = 0
            
            for func in functions[:20]:  # Limit analysis for performance
                func_addr = func.get("offset", 0)
                
                try:
                    # Get function instructions
                    instructions = binary.r2.cmdj(f"pdfj @ {func_addr}")
                    if not instructions or "ops" not in instructions:
                        continue
                    
                    ops = instructions["ops"]
                    
                    # Look for metamorphic indicators
                    dead_code_count = 0
                    nop_count = 0
                    redundant_moves = 0
                    
                    for op in ops:
                        opcode = op.get("opcode", "").lower()
                        
                        # Count NOPs
                        if "nop" in opcode:
                            nop_count += 1
                        
                        # Count redundant moves (mov reg, reg)
                        if "mov" in opcode and len(opcode.split()) >= 3:
                            parts = opcode.split()
                            if len(parts) >= 3:
                                src = parts[2].rstrip(',')
                                dst = parts[1].rstrip(',')
                                if src == dst:
                                    redundant_moves += 1
                        
                        # Count potentially dead arithmetic
                        if any(instr in opcode for instr in ["add", "sub", "xor"]) and "0" in opcode:
                            dead_code_count += 1
                    
                    # Calculate polymorphic score
                    total_ops = len(ops)
                    if total_ops > 0:
                        poly_score = (dead_code_count + nop_count + redundant_moves) / total_ops
                        
                        if poly_score > 0.3:  # 30% threshold
                            polymorphic_functions += 1
                            result["indicators"].append(
                                f"Function at 0x{func_addr:x} has {poly_score:.1%} polymorphic indicators"
                            )
                
                except Exception:
                    continue
            
            # Calculate overall results
            if total_functions > 0:
                result["polymorphic_ratio"] = polymorphic_functions / total_functions
                
                if result["polymorphic_ratio"] > 0.2:  # 20% of functions
                    result["detected"] = True
                    result["confidence"] = min(1.0, result["polymorphic_ratio"] * 2)
            
        except Exception as e:
            logger.error(f"Metamorphic detection failed: {e}")
        
        return result
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        
        # Calculate entropy
        length = len(data)
        entropy = 0.0
        
        for count in frequencies.values():
            if count > 0:
                probability = count / length
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _get_entry_bytes(self, binary: Binary, size: int = 32) -> bytes:
        """Get bytes at entry point."""
        try:
            entry_point = binary.info.get("bin", {}).get("baddr", 0)
            entry_hex = binary.r2.cmd(f"p8 {size} @ {entry_point}")
            return bytes.fromhex(entry_hex.strip()) if entry_hex.strip() else b""
        except Exception:
            return b""
    
    def get_comprehensive_report(self, binary: Binary) -> Dict[str, Any]:
        """
        Generate comprehensive obfuscation analysis report.
        
        Args:
            binary: Binary to analyze
            
        Returns:
            Complete analysis report
        """
        report = {
            "timestamp": "",
            "binary_info": {},
            "packer_analysis": {},
            "obfuscation_analysis": {},
            "virtualization_analysis": {},
            "layer_analysis": {},
            "metamorphic_analysis": {},
            "recommendations": []
        }
        
        try:
            import datetime
            report["timestamp"] = datetime.datetime.now().isoformat()
            
            # Basic binary info
            report["binary_info"] = {
                "path": binary.filepath if hasattr(binary, 'filepath') else "unknown",
                "format": binary.info.get("bin", {}).get("class", "unknown"),
                "architecture": binary.info.get("bin", {}).get("machine", "unknown"),
                "bits": binary.info.get("bin", {}).get("bits", 0)
            }
            
            # Comprehensive analysis
            basic_result = self.analyze_binary(binary)
            report["obfuscation_analysis"] = basic_result.__dict__
            
            # Extended analysis
            report["virtualization_analysis"] = self.detect_custom_virtualizer(binary)
            report["layer_analysis"] = self.detect_code_packing_layers(binary)
            report["metamorphic_analysis"] = self.detect_metamorphic_engine(binary)
            
            # Generate recommendations
            recommendations = []
            
            if basic_result.vm_detected:
                recommendations.append("VM protection detected - use devirtualization techniques")
            
            if basic_result.mba_expressions_found > 0:
                recommendations.append("MBA expressions found - apply expression simplification")
            
            if report["layer_analysis"]["layers_detected"] > 1:
                recommendations.append("Multiple packing layers detected - iterative unpacking required")
            
            if report["metamorphic_analysis"]["detected"]:
                recommendations.append("Metamorphic code detected - use pattern-based analysis")
            
            if basic_result.requires_dynamic_analysis:
                recommendations.append("Dynamic analysis recommended for complete deobfuscation")
            
            report["recommendations"] = recommendations
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            report["errors"] = [str(e)]
        
        return report