"""
Binary class for handling binary executables with r2pipe.
"""

import logging
import shutil
from pathlib import Path
from typing import Any

import r2pipe

logger = logging.getLogger(__name__)


class Binary:
    """
    Represents a binary executable and provides an interface to radare2 through r2pipe.

    Attributes:
        path: Path to the binary file
        r2: r2pipe connection instance
        info: Binary metadata from radare2
    """

    def __init__(self, path: str | Path, flags: list[str] | None = None, writable: bool = False, low_memory: bool = False):
        """
        Initialize a Binary instance.

        Args:
            path: Path to the binary file
            flags: Optional list of radare2 flags (e.g., ['-2', '-A'])
            writable: If True, open binary in write mode
            low_memory: If True, configure r2 for low memory usage (prevents OOM on large binaries)

        Raises:
            FileNotFoundError: If binary file doesn't exist
            RuntimeError: If r2pipe connection fails
        """
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"Binary not found: {self.path}")

        self.flags = flags or ["-2"]
        if writable:
            self.flags.append("-w")

        self.r2: r2pipe.open_sync.open | None = None
        self.info: dict[str, Any] = {}
        self._analyzed = False
        self._writable = writable
        self._low_memory = low_memory
        self._functions_cache: list[dict[str, Any]] | None = None
        self._mutation_counter = 0  # Track mutations for batch processing

    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def open(self) -> "Binary":
        """
        Open the binary with r2pipe.

        Returns:
            Self for method chaining
        """
        try:
            logger.info(f"Opening binary: {self.path}")
            self.r2 = r2pipe.open(str(self.path), flags=self.flags)
            self.info = self.r2.cmdj("ij") or {}

            # Configure r2 for low memory usage on large binaries
            if self._low_memory:
                logger.debug("Configuring r2 for low memory mode")
                self.r2.cmd("e bin.cache=false")  # Disable binary cache
                self.r2.cmd("e io.cache=false")   # Disable I/O cache
                self.r2.cmd("e bin.strings=false") # Don't cache strings

            logger.debug(f"Binary info: {self.info.get('core', {}).get('format', 'unknown')}")
        except Exception as e:
            raise RuntimeError(f"Failed to open binary with r2pipe: {e}")
        return self

    def close(self):
        """Close the r2pipe connection."""
        if self.r2:
            self.r2.quit()
            self.r2 = None
            logger.info(f"Closed binary: {self.path}")

    def reload(self):
        """
        Reload r2 connection (close and reopen).

        This is useful for batch processing on large binaries to release
        accumulated memory in radare2 process, preventing OOM crashes.
        """
        logger.debug("Reloading r2 connection to free memory")
        was_analyzed = self._analyzed
        self.close()
        self.open()
        # Restore analyzed state (cache is preserved separately)
        self._analyzed = was_analyzed

    def analyze(self, level: str = "aaa") -> "Binary":
        """
        Run radare2 analysis on the binary.

        Args:
            level: Analysis level (aa, aaa, aaaa, etc.)
                - aa: basic analysis (~5-10s for large binaries)
                - aaa: analyze all referenced code (~2-3min for 7k+ functions)
                - aaaa: experimental analysis (very slow)

        Returns:
            Self for method chaining
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        logger.info(f"Running analysis: {level}")

        # Warn about slow analysis
        if level in ["aaa", "aaaa"]:
            logger.warning("Analysis may take 2-5 minutes for large binaries. Please wait...")

        self.r2.cmd(level)
        self._analyzed = True

        # Cache functions after analysis to avoid repeated expensive r2 calls
        try:
            self._functions_cache = self.r2.cmdj("aflj") or []
            logger.info(f"Analysis complete - cached {len(self._functions_cache)} functions")
        except Exception as e:
            logger.warning(f"Failed to cache functions: {e}")
            self._functions_cache = None

        return self

    def get_functions(self) -> list[dict[str, Any]]:
        """
        Get list of functions in the binary.

        Returns cached functions after analysis to avoid expensive r2 queries.

        Returns:
            List of function dictionaries with metadata
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        # Use cached functions if available (set during analyze())
        if self._functions_cache is not None:
            logger.debug(f"Using cached {len(self._functions_cache)} functions")
            return self._functions_cache

        # Fallback to querying r2 if no cache
        functions = self.r2.cmdj("aflj") or []
        logger.debug(f"Found {len(functions)} functions (uncached)")
        return functions

    def get_function_disasm(self, address: int) -> list[dict[str, Any]]:
        """
        Get disassembly of a function at given address.

        Args:
            address: Function address

        Returns:
            List of instruction dictionaries
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        disasm = self.r2.cmdj(f"pdfj @ {address}") or {}
        return disasm.get("ops", [])

    def get_basic_blocks(self, address: int) -> list[dict[str, Any]]:
        """
        Get basic blocks for a function at given address.

        Args:
            address: Function address

        Returns:
            List of basic block dictionaries
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        blocks = self.r2.cmdj(f"afbj @ {address}") or []
        return blocks

    def get_sections(self) -> list[dict[str, Any]]:
        """
        Get sections from the binary.

        Returns:
            List of section dictionaries with keys like name, size, vaddr, etc.
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        sections = self.r2.cmdj("iSj") or []
        return sections

    def _resolve_symbolic_vars(self, instruction: str, function_addr: int | None = None) -> str:
        """
        Resolve symbolic variable names in instruction to actual addresses.

        Converts var_XXh to [rsp+offset] or [rbp-offset] based on function analysis.

        Args:
            instruction: Assembly instruction with symbolic vars (e.g., "mov eax, [var_10h]")
            function_addr: Function address for variable context (optional)

        Returns:
            Instruction with resolved addresses
        """
        import re

        if not self.r2:
            return instruction

        # Pattern to match symbolic variables: var_XXh, var_bp_XXh, arg_XXh, and suffixed versions (var_XXh_2, etc.)
        var_pattern = r"\[(var_(?:bp_)?|arg_)([0-9a-f]+)h(_\d+)?\]"
        matches = list(re.finditer(var_pattern, instruction, re.IGNORECASE))

        if not matches:
            return instruction

        # Get variable and argument information from current function if available
        var_map = {}
        if function_addr:
            try:
                # Get function variables and arguments with afv command
                vars_output = self.r2.cmd(f"afv @ {function_addr}")
                # Parse output like:
                # "var int64_t var_20h @ rsp+0x20"
                # "arg int64_t arg1 @ rcx"
                for line in vars_output.split("\n"):
                    if ("var_" in line or "arg" in line) and "@" in line:
                        parts = line.split("@")
                        if len(parts) == 2:
                            var_name = parts[0].split()[-1].strip()
                            location = parts[1].strip()
                            var_map[var_name] = location
            except Exception:
                pass

        # Replace variables with resolved addresses
        resolved = instruction
        for match in reversed(matches):  # Reverse to maintain positions
            prefix = match.group(1)  # "var_", "var_bp_", or "arg_"
            offset_hex = match.group(2)
            suffix = match.group(3) or ""  # "_2", "_3", etc. or empty string
            offset = int(offset_hex, 16)

            # Construct variable name (including suffix if present)
            if prefix == "var_bp_":
                var_name = f"var_bp_{offset_hex}h{suffix}"
            elif prefix == "var_":
                var_name = f"var_{offset_hex}h{suffix}"
            else:  # arg_
                var_name = f"arg_{offset_hex}h{suffix}"

            # Try to get from function analysis first
            if var_name in var_map:
                replacement = f"[{var_map[var_name]}]"
            else:
                # Fallback: construct based on naming convention
                if prefix == "var_bp_":
                    # var_bp_XXh means [rbp - offset]
                    replacement = f"[rbp - 0x{offset:x}]"
                elif prefix == "arg_":
                    # arg_XXh typically means [rsp + offset] or [rbp + offset]
                    # Arguments are typically above the stack frame
                    replacement = f"[rsp + 0x{offset:x}]"
                else:
                    # var_XXh typically means [rsp + offset]
                    replacement = f"[rsp + 0x{offset:x}]"

            resolved = resolved[: match.start()] + replacement + resolved[match.end() :]

        return resolved

    def _normalize_assembly_syntax(self, instruction: str) -> str:
        """
        Normalize assembly syntax to work around radare2 assembler quirks.

        Args:
            instruction: Assembly instruction

        Returns:
            Normalized instruction
        """
        # No longer removing size specifiers with segment prefixes
        # The segment prefix fallback will handle these correctly
        return instruction

    def _assemble_movzx_movsx_fallback(self, instruction: str) -> bytes | None:
        """
        Manually encode movzx/movsx instructions using direct opcodes.

        Radare2's assembler fails on register-to-register movzx/movsx but works on memory operands.
        This fallback manually constructs the opcodes for reg-to-reg cases.

        Args:
            instruction: movzx/movsx instruction (e.g., "movzx eax, bl")

        Returns:
            Assembled bytes or None if cannot encode
        """
        import re

        # Parse instruction: movzx/movsx dest, src
        match = re.match(r'(movzx|movsx)\s+(\w+),\s*(\w+)', instruction.strip(), re.IGNORECASE)
        if not match:
            return None

        mnemonic, dest, src = match.groups()
        mnemonic = mnemonic.lower()
        dest = dest.lower()
        src = src.lower()

        # Register encoding tables
        reg32_encoding = {
            "eax": 0, "ecx": 1, "edx": 2, "ebx": 3,
            "esp": 4, "ebp": 5, "esi": 6, "edi": 7,
        }
        reg16_encoding = {
            "ax": 0, "cx": 1, "dx": 2, "bx": 3,
            "sp": 4, "bp": 5, "si": 6, "di": 7,
        }
        reg8_encoding = {
            "al": 0, "cl": 1, "dl": 2, "bl": 3,
            "ah": 4, "ch": 5, "dh": 6, "bh": 7,
        }
        reg64_encoding = {
            "rax": 0, "rcx": 1, "rdx": 2, "rbx": 3,
            "rsp": 4, "rbp": 5, "rsi": 6, "rdi": 7,
        }

        # Determine opcode based on source size and operation
        if src in reg8_encoding:
            # Source is 8-bit
            opcode = bytes([0x0F, 0xB6 if mnemonic == "movzx" else 0xBE])
            src_code = reg8_encoding[src]
        elif src in reg16_encoding:
            # Source is 16-bit
            opcode = bytes([0x0F, 0xB7 if mnemonic == "movzx" else 0xBF])
            src_code = reg16_encoding[src]
        else:
            # Unknown source register size
            return None

        # Determine destination encoding
        if dest in reg32_encoding:
            dest_code = reg32_encoding[dest]
        elif dest in reg64_encoding:
            # 64-bit destination requires REX.W prefix
            dest_code = reg64_encoding[dest]
            opcode = bytes([0x48]) + opcode  # REX.W prefix
        else:
            return None

        # Construct ModR/M byte: 11 (register mode) + dest<<3 + src
        modrm = 0xC0 | (dest_code << 3) | src_code

        return opcode + bytes([modrm])

    def _assemble_segment_prefix_fallback(self, instruction: str) -> bytes | None:
        """
        Manually encode instructions with segment prefixes (fs:, gs:, etc.).

        Radare2's assembler fails on segment-prefixed instructions.
        This fallback removes the segment prefix, assembles without it, then adds the prefix byte.

        Args:
            instruction: Instruction with segment prefix (e.g., "mov fs:[rax], ecx")

        Returns:
            Assembled bytes with segment prefix or None if failed
        """
        import re

        # Segment prefix bytes
        segment_prefixes = {
            "es:": 0x26,
            "cs:": 0x2E,
            "ss:": 0x36,
            "ds:": 0x3E,
            "fs:": 0x64,
            "gs:": 0x65,
        }

        # Find which segment prefix is used
        segment_byte = None
        instruction_without_segment = instruction
        for seg_name, seg_byte in segment_prefixes.items():
            if seg_name in instruction.lower():
                segment_byte = seg_byte
                # Remove only the segment prefix, keep size specifiers
                # "mov dword fs:[rax], ecx" -> "mov dword [rax], ecx"
                instruction_without_segment = instruction.replace(seg_name, '', 1)
                instruction_without_segment = instruction_without_segment.replace(seg_name.upper(), '', 1)
                break

        if segment_byte is None:
            return None

        # Try to assemble the instruction without the segment prefix
        if not self.r2:
            return None

        result = self.r2.cmd(f"pa {instruction_without_segment}")
        hex_str = result.strip()
        if hex_str:
            base_bytes = bytes.fromhex(hex_str)
            # Prepend segment prefix byte
            return bytes([segment_byte]) + base_bytes

        return None

    def assemble(self, instruction: str, function_addr: int | None = None) -> bytes | None:
        """
        Assemble an instruction using radare2's rasm2 with intelligent fallbacks.

        Args:
            instruction: Assembly instruction (e.g., "nop", "xor eax, eax")
            function_addr: Function address for resolving symbolic variables (optional)

        Returns:
            Assembled bytes or None if failed
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        try:
            # Resolve symbolic variables to actual addresses
            resolved_instruction = self._resolve_symbolic_vars(instruction, function_addr)

            # Normalize syntax for radare2 assembler compatibility
            normalized_instruction = self._normalize_assembly_syntax(resolved_instruction)

            # Try standard radare2 assembler first
            result = self.r2.cmd(f"pa {normalized_instruction}")
            hex_str = result.strip()
            if hex_str:
                return bytes.fromhex(hex_str)

            # If radare2 failed, try intelligent fallbacks

            # Fallback 1: movzx/movsx manual encoding
            if normalized_instruction.strip().lower().startswith(("movzx", "movsx")):
                logger.debug(f"Radare2 assembler failed, trying manual movzx/movsx encoding")
                manual_bytes = self._assemble_movzx_movsx_fallback(normalized_instruction)
                if manual_bytes:
                    logger.debug(f"  Successfully encoded: {manual_bytes.hex()}")
                    return manual_bytes

            # Fallback 2: segment prefix instructions (fs:, gs:, etc.)
            if any(seg in normalized_instruction.lower() for seg in ["fs:", "gs:", "es:", "ds:", "ss:", "cs:"]):
                logger.debug(f"Radare2 assembler failed, trying segment prefix fallback")
                segment_bytes = self._assemble_segment_prefix_fallback(normalized_instruction)
                if segment_bytes:
                    logger.debug(f"  Successfully encoded: {segment_bytes.hex()}")
                    return segment_bytes

            # All fallbacks exhausted
            logger.error(f"Failed to assemble: {instruction}")
            if normalized_instruction != instruction:
                logger.debug(f"  After normalization: {normalized_instruction}")
            return None

        except Exception as e:
            logger.error(f"Assembly error for '{instruction}': {e}")
            return None

    def track_mutation(self, batch_size: int = 1000):
        """
        Track mutation count and reload r2 periodically for batch processing.

        This prevents OOM on large binaries by restarting r2 every N mutations.

        Args:
            batch_size: Number of mutations before reloading r2 (default: 1000)
        """
        if not self._low_memory:
            return

        self._mutation_counter += 1
        if self._mutation_counter % batch_size == 0:
            logger.info(
                f"Batch checkpoint: {self._mutation_counter} mutations applied. "
                f"Reloading r2 to free memory..."
            )
            self.reload()

    def write_bytes(self, address: int, data: bytes) -> bool:
        """
        Write bytes to binary at specified address.

        Args:
            address: Target virtual address (will be converted to physical offset)
            data: Bytes to write

        Returns:
            True if successful
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        if not self._writable:
            logger.warning("Binary opened in read-only mode, write may fail")

        try:
            paddr_result = self.r2.cmd(f"s2p 0x{address:x}")

            if not paddr_result or paddr_result.strip() == "":
                physical_offset = address
                logger.debug(f"Using address directly as physical offset: 0x{address:x}")
            else:
                try:
                    physical_offset = int(paddr_result.strip(), 16)
                    logger.debug(f"Converted vaddr 0x{address:x} -> paddr 0x{physical_offset:x}")
                except ValueError:
                    physical_offset = address
                    logger.debug(f"Could not parse paddr, using direct: 0x{address:x}")

            with open(self.path, "r+b") as f:
                f.seek(physical_offset)
                f.write(data)
            logger.debug(f"Wrote {len(data)} bytes at physical offset 0x{physical_offset:x}")

            # Track mutation for batch processing
            self.track_mutation()

            return True
        except Exception as e:
            logger.error(f"Failed to write bytes at 0x{address:x}: {e}")
            return False

    def write_instruction(self, address: int, instruction: str) -> bool:
        """
        Assemble and write an instruction at specified address.

        Args:
            address: Target address
            instruction: Assembly instruction

        Returns:
            True if successful
        """
        assembled = self.assemble(instruction)
        if assembled:
            return self.write_bytes(address, assembled)
        return False

    def nop_fill(self, address: int, size: int) -> bool:
        """
        Fill a region with NOPs.

        Args:
            address: Start address
            size: Number of bytes to fill

        Returns:
            True if successful
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        nop_bytes = b"\x90" * size
        return self.write_bytes(address, nop_bytes)

    def save(self, output_path: str | Path | None = None):
        """
        Save modified binary to file.

        Args:
            output_path: Output file path. If None, keeps current file.
        """
        if not self.r2:
            raise RuntimeError("Binary not opened. Call open() first.")

        if output_path and output_path != self.path:
            output_path = Path(output_path)

            shutil.copy2(self.path, output_path)
            logger.info(f"Copied binary to: {output_path}")
        else:
            logger.info(f"Changes already written to: {self.path}")

    def get_arch_info(self) -> dict[str, Any]:
        """
        Get architecture information from the binary.

        Returns:
            Dictionary with arch, bits, endian, etc.
        """
        core_info = self.info.get("bin", {})
        return {
            "arch": core_info.get("arch", "unknown"),
            "bits": core_info.get("bits", 0),
            "endian": core_info.get("endian", "unknown"),
            "format": core_info.get("class", "unknown"),
            "machine": core_info.get("machine", "unknown"),
        }

    def is_analyzed(self) -> bool:
        """Check if binary has been analyzed."""
        return self._analyzed
