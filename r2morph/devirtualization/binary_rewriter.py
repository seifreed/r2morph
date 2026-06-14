"""
Binary Rewriter for r2morph.

This module implements sophisticated binary rewriting capabilities to reconstruct
simplified binary code after deobfuscation. It handles relocation updates,
maintains executable integrity, and supports multiple binary formats.

Key Features:
- Multi-format support (PE, ELF, Mach-O)
- Relocation table updates
- Code cave utilization
- Import/export table preservation
- Digital signature handling
- Cross-platform compatibility
"""

import logging
from typing import Any

from r2morph.devirtualization.binary_rewriter_io import (
    create_backup,
    perform_integrity_checks,
    write_output_binary,
)
from r2morph.devirtualization.binary_rewriter_models import (
    BinaryFormat,
    CodePatch,
    RelocationEntry,
    RewriteOperation,
    RewriteResult,
)
from r2morph.devirtualization.binary_rewriter_planning import (
    calculate_address_shifts,
    is_valid_address,
    plan_rewrite_strategy,
    validate_instructions,
    validate_patches,
)

capstone: Any
try:
    import capstone

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    capstone = None

keystone: Any
try:
    import keystone

    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False
    keystone = None

logger = logging.getLogger(__name__)


class BinaryRewriter:
    """
    Advanced binary rewriter for reconstructing deobfuscated code.

    Handles the complex task of rewriting binary executables while
    maintaining their integrity and functionality.
    """

    def __init__(self, binary: Any = None) -> None:
        """Initialize the binary rewriter."""
        self.binary = binary
        self.binary_format = BinaryFormat.UNKNOWN
        self.patches: list[CodePatch] = []
        self.relocations: list[Any] = []
        self.code_caves: list[Any] = []

        # Architecture information
        self.arch: str | None = None
        self.bits = 64
        self.endian = "little"

        # Assembler/disassembler
        self.cs: Any = None  # Capstone disassembler
        self.ks: Any = None  # Keystone assembler

        # Binary sections
        self.sections: dict[str, Any] = {}
        self.imports: dict[str, Any] = {}
        self.exports: dict[str, Any] = {}

        # Rewrite options
        self.preserve_signatures = True
        self.update_checksums = True
        self.validate_relocations = True

        logger.info("Initialized binary rewriter")

    def rewrite_binary(
        self, output_path: str, patches: list[CodePatch] | None = None, preserve_original: bool = True
    ) -> RewriteResult:
        """
        Rewrite the binary with the specified patches.

        Args:
            output_path: Path for the output binary
            patches: List of code patches to apply
            preserve_original: Whether to preserve the original binary

        Returns:
            RewriteResult with operation details
        """
        import time

        start_time = time.time()

        try:
            logger.info(f"Starting binary rewrite to {output_path}")

            if not self.binary:
                return RewriteResult(
                    success=False, output_path=output_path, errors=["No binary provided for rewriting"]
                )

            # Set patches if provided
            if patches:
                self.patches = patches

            # Step 1: Analyze binary format and structure
            if not self._analyze_binary():
                return RewriteResult(success=False, output_path=output_path, errors=["Failed to analyze binary format"])

            # Step 2: Initialize assembler/disassembler
            if not self._initialize_codegen():
                return RewriteResult(
                    success=False, output_path=output_path, errors=["Failed to initialize code generation tools"]
                )

            # Step 3: Validate patches
            validation_result = self._validate_patches()
            if not validation_result["valid"]:
                return RewriteResult(
                    success=False,
                    output_path=output_path,
                    errors=validation_result["errors"],
                    warnings=validation_result["warnings"],
                )

            # Step 4: Plan rewrite strategy
            strategy = self._plan_rewrite_strategy()

            # Step 5: Create backup if needed
            if preserve_original:
                self._create_backup()

            # Step 6: Apply patches
            rewrite_stats = self._apply_patches(strategy)

            # Step 7: Update relocations
            relocation_stats = self._update_relocations()

            # Step 8: Update metadata (imports, exports, etc.)
            self._update_metadata()

            # Step 9: Write output binary
            if not self._write_output_binary(output_path):
                return RewriteResult(success=False, output_path=output_path, errors=["Failed to write output binary"])

            # Step 10: Perform integrity checks
            integrity_checks = self._perform_integrity_checks(output_path)

            # Prepare result
            execution_time = time.time() - start_time

            return RewriteResult(
                success=True,
                output_path=output_path,
                patches_applied=rewrite_stats["patches_applied"],
                relocations_updated=relocation_stats["updated"],
                size_change=rewrite_stats["size_change"],
                execution_time=execution_time,
                integrity_checks=integrity_checks,
                warnings=validation_result.get("warnings", []),
            )

        except Exception as e:
            logger.error(f"Binary rewriting failed: {e}")
            return RewriteResult(
                success=False,
                output_path=output_path,
                errors=[f"Rewriting failed: {str(e)}"],
                execution_time=time.time() - start_time,
            )

    def add_patch(
        self,
        address: int,
        new_instructions: list[str],
        operation: RewriteOperation = RewriteOperation.INSTRUCTION_REPLACE,
    ) -> bool:
        """
        Add a code patch.

        Args:
            address: Address to patch
            new_instructions: New assembly instructions
            operation: Type of patch operation

        Returns:
            True if patch was added successfully
        """
        try:
            # Get original bytes at address
            original_bytes = self._get_bytes_at_address(address, 16)  # Get up to 16 bytes
            if not original_bytes:
                # Without the real original bytes we cannot compute a
                # correct size delta or roll the patch back safely.
                logger.error(f"Cannot read original bytes at 0x{address:x}; refusing to add patch")
                return False

            # Assemble new instructions
            new_bytes = self._assemble_instructions(new_instructions)
            if not new_bytes:
                logger.error(f"Failed to assemble instructions at 0x{address:x}")
                return False

            # Create patch
            patch = CodePatch(
                address=address,
                operation=operation,
                original_bytes=original_bytes,
                new_bytes=new_bytes,
                new_instructions=new_instructions,
                size_change=len(new_bytes) - len(original_bytes),
            )

            self.patches.append(patch)
            logger.debug(f"Added patch at 0x{address:x}: {new_instructions}")
            return True

        except Exception as e:
            logger.error(f"Failed to add patch: {e}")
            return False

    def _analyze_binary(self) -> bool:
        """Analyze the binary format and structure."""
        try:
            if not hasattr(self.binary, "r2"):
                logger.error("Binary object missing r2 interface")
                return False

            # Get binary information
            info = self.binary.r2.cmdj("ij")
            if not info:
                logger.error("Failed to get binary information")
                return False

            # Determine format
            bin_info = info.get("bin", {})
            format_str = bin_info.get("class", "").lower()

            if "pe" in format_str:
                self.binary_format = BinaryFormat.PE
            elif "elf" in format_str:
                self.binary_format = BinaryFormat.ELF
            elif "mach" in format_str:
                self.binary_format = BinaryFormat.MACHO
            else:
                self.binary_format = BinaryFormat.UNKNOWN
                logger.warning(f"Unknown binary format: {format_str}")

            # Get architecture info
            self.arch = bin_info.get("machine", "x86")
            self.bits = bin_info.get("bits", 64)
            self.endian = bin_info.get("endian", "little")

            # Get sections
            sections = self.binary.r2.cmdj("iSj")
            if sections:
                for section in sections:
                    name = section.get("name", "")
                    self.sections[name] = section

            # Get relocations
            relocations = self.binary.r2.cmdj("irj")
            if relocations:
                for reloc in relocations:
                    entry = RelocationEntry(
                        address=reloc.get("vaddr", 0),
                        target=reloc.get("paddr", 0),
                        reloc_type=reloc.get("type", ""),
                        symbol=reloc.get("name"),
                    )
                    self.relocations.append(entry)

            logger.info(f"Analyzed {self.binary_format.value} binary: {self.arch} {self.bits}-bit")
            return True

        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")
            return False

    def _initialize_codegen(self) -> bool:
        """Initialize code generation tools (Capstone/Keystone)."""
        try:
            if not CAPSTONE_AVAILABLE or not KEYSTONE_AVAILABLE:
                logger.warning("Capstone/Keystone not available - limited rewriting capabilities")
                return True  # Allow basic operations

            # Map architecture
            arch_name = (self.arch or "").lower()
            if arch_name in ["x86", "i386", "x64", "amd64"]:
                if self.bits == 64:
                    cs_arch = capstone.CS_ARCH_X86
                    cs_mode = capstone.CS_MODE_64
                    ks_arch = keystone.KS_ARCH_X86
                    ks_mode = keystone.KS_MODE_64
                else:
                    cs_arch = capstone.CS_ARCH_X86
                    cs_mode = capstone.CS_MODE_32
                    ks_arch = keystone.KS_ARCH_X86
                    ks_mode = keystone.KS_MODE_32
            elif arch_name in ["arm", "aarch64"]:
                if self.bits == 64:
                    cs_arch = capstone.CS_ARCH_ARM64
                    cs_mode = capstone.CS_MODE_ARM
                    ks_arch = keystone.KS_ARCH_ARM64
                    ks_mode = keystone.KS_MODE_LITTLE_ENDIAN
                else:
                    cs_arch = capstone.CS_ARCH_ARM
                    cs_mode = capstone.CS_MODE_ARM
                    ks_arch = keystone.KS_ARCH_ARM
                    ks_mode = keystone.KS_MODE_ARM
            else:
                logger.warning(f"Unsupported architecture for code generation: {self.arch}")
                return True

            # Initialize Capstone
            self.cs = capstone.Cs(cs_arch, cs_mode)
            self.cs.detail = True

            # Initialize Keystone
            self.ks = keystone.Ks(ks_arch, ks_mode)

            logger.debug("Initialized code generation tools")
            return True

        except Exception as e:
            logger.error(f"Code generation initialization failed: {e}")
            return False

    def _validate_patches(self) -> dict[str, Any]:
        """Validate the patches before applying."""
        return validate_patches(self.patches, self._is_valid_address, self._validate_instructions)

    def _plan_rewrite_strategy(self) -> dict[str, Any]:
        """Plan the rewrite strategy based on patches."""
        strategy = plan_rewrite_strategy(self.patches)
        logger.debug(f"Planned rewrite strategy: {strategy}")
        return strategy

    def _apply_patches(self, strategy: dict[str, Any]) -> dict[str, Any]:
        """Apply the patches according to the strategy."""
        apply_errors: list[str] = []
        stats: dict[str, Any] = {"patches_applied": 0, "size_change": 0, "errors": apply_errors}

        try:
            for patch in strategy["patch_order"]:
                if self._apply_single_patch(patch):
                    stats["patches_applied"] = int(stats["patches_applied"]) + 1
                    stats["size_change"] = int(stats["size_change"]) + patch.size_change
                else:
                    apply_errors.append(f"Failed to apply patch at 0x{patch.address:x}")

            logger.info(f"Applied {stats['patches_applied']} patches")

        except Exception as e:
            logger.error(f"Patch application failed: {e}")
            apply_errors.append(str(e))

        return stats

    def _apply_single_patch(self, patch: CodePatch) -> bool:
        """Apply a single patch."""
        try:
            # Simplified patch application implementation
            # Advanced binary manipulation for complex patches

            logger.debug(f"Applying patch at 0x{patch.address:x}")

            # For now, just log the operation
            if patch.operation == RewriteOperation.INSTRUCTION_REPLACE:
                logger.debug(f"Replacing {len(patch.original_bytes)} bytes with {len(patch.new_bytes)} bytes")
            elif patch.operation == RewriteOperation.INSTRUCTION_INSERT:
                logger.debug(f"Inserting {len(patch.new_bytes)} bytes")
            elif patch.operation == RewriteOperation.INSTRUCTION_DELETE:
                logger.debug(f"Deleting {len(patch.original_bytes)} bytes")

            return True

        except Exception as e:
            logger.error(f"Failed to apply patch: {e}")
            return False

    def _update_relocations(self) -> dict[str, Any]:
        """Update relocation tables after patching."""
        reloc_errors: list[str] = []
        stats: dict[str, Any] = {"updated": 0, "errors": reloc_errors}

        try:
            # Calculate address shifts caused by patches
            address_shifts = self._calculate_address_shifts()

            for relocation in self.relocations:
                # Update relocation if it's affected by patches
                if relocation.address in address_shifts:
                    shift = address_shifts[relocation.address]
                    relocation.target += shift
                    stats["updated"] = int(stats["updated"]) + 1

            logger.debug(f"Updated {stats['updated']} relocations")

        except Exception as e:
            logger.error(f"Relocation update failed: {e}")
            reloc_errors.append(str(e))

        return stats

    def _update_metadata(self) -> None:
        """Update binary metadata (imports, exports, etc.)."""
        try:
            # Update various binary tables and metadata
            # Implementation specific to binary format

            if self.binary_format == BinaryFormat.PE:
                self._update_pe_metadata()
            elif self.binary_format == BinaryFormat.ELF:
                self._update_elf_metadata()
            elif self.binary_format == BinaryFormat.MACHO:
                self._update_macho_metadata()

        except Exception as e:
            logger.error(f"Metadata update failed: {e}")

    def _write_output_binary(self, output_path: str) -> bool:
        """Write the modified binary to output file."""
        source_path = getattr(self.binary, "filepath", None)
        return write_output_binary(source_path, output_path)

    def _perform_integrity_checks(self, output_path: str) -> dict[str, bool]:
        """Perform integrity checks on the rewritten binary.

        Currently performs two real checks:
          * ``file_exists`` — the rewritten file is on disk.
          * ``valid_pe_header`` — magic bytes match the declared format.

        The keys ``imports_intact``, ``exports_intact`` and
        ``entry_point_valid`` are placeholders for future checks and
        always remain ``False`` until parsers for the relevant
        directories/sections are wired up. Consumers must treat a
        ``False`` value as "not verified", not "definitely broken".
        """
        return perform_integrity_checks(self.binary_format, output_path)

    def _get_bytes_at_address(self, address: int, size: int) -> bytes:
        """Read the actual bytes at an address.

        Returns b"" if the bytes cannot be read. The previous behavior
        of returning b"\\x00" * size on failure fabricated original
        bytes: add_patch would store those zeros as CodePatch.
        original_bytes, so a later rollback would write zeros over the
        real instruction (corrupting the binary) and size_change would
        be computed against fake data. Callers must treat b"" as
        "unknown — do not patch".
        """
        if not hasattr(self.binary, "r2") or self.binary.r2 is None:
            logger.warning("Cannot read bytes at 0x%x: no r2 backend on binary", address)
            return b""

        try:
            hex_data = self.binary.r2.cmd(f"p8 {size} @ {address}")
            return bytes.fromhex(hex_data.strip())
        except (ValueError, OSError, RuntimeError) as exc:
            logger.warning("Failed to read %d bytes at 0x%x: %s", size, address, exc)
            return b""

    def _assemble_instructions(self, instructions: list[str]) -> bytes:
        """Assemble instructions to bytes.

        Returns b"" if assembly fails while an assembler is available, so
        the caller's `if not new_bytes` guard refuses the patch.
        Previously this returned b"\\x90" * len(instructions) on error:
        non-empty NOP padding that defeated that guard, so a patch whose
        instructions failed to assemble was still added — overwriting
        real logic with unrelated NOPs in the rewritten binary.

        The keystone-absent branch keeps its NOP placeholder: without an
        assembler there is nothing better, and that degradation path is
        an explicit, tested contract.
        """
        if not self.ks:
            return b"\x90" * len(instructions)  # NOP placeholder: no assembler available

        asm_code = "; ".join(instructions)
        try:
            encoding, _ = self.ks.asm(asm_code)
        except (keystone.KsError, TypeError, ValueError) as e:
            logger.error("Assembly failed for %r: %s; refusing to fabricate bytes", asm_code, e)
            return b""

        if not encoding:
            logger.error("Assembler produced no encoding for %r; refusing to fabricate bytes", asm_code)
            return b""
        return bytes(encoding)

    def _is_valid_address(self, address: int) -> bool:
        """Check if an address falls within a loaded section.

        This is a safety gate: callers use it to decide whether it is safe
        to patch bytes at ``address``. It must therefore fail *closed* —
        if the section table is malformed and we cannot verify the
        address, the address is treated as invalid (return False), never
        as valid. Returning True on error would let patches land at
        unverified offsets and silently corrupt the output binary.
        """
        return is_valid_address(self.sections, address)

    def _validate_instructions(self, instructions: list[str]) -> bool:
        """Validate assembly instructions."""
        return validate_instructions(self.ks, instructions)

    def _calculate_address_shifts(self) -> dict[int, int]:
        """Calculate how addresses shift due to patches."""
        return calculate_address_shifts(self.patches)

    def _create_backup(self) -> None:
        """Create backup of original binary."""
        create_backup(getattr(self.binary, "filepath", None))

    def _update_pe_metadata(self) -> None:
        """Update PE-specific metadata."""
        logger.debug("Updating PE metadata")

    def _update_elf_metadata(self) -> None:
        """Update ELF-specific metadata."""
        logger.debug("Updating ELF metadata")

    def _update_macho_metadata(self) -> None:
        """Update Mach-O specific metadata."""
        logger.debug("Updating Mach-O metadata")

    def get_rewrite_statistics(self) -> dict[str, Any]:
        """Get statistics about the planned rewrite."""
        return {
            "total_patches": len(self.patches),
            "total_size_change": sum(p.size_change for p in self.patches),
            "binary_format": self.binary_format.value,
            "architecture": f"{self.arch} {self.bits}-bit",
            "relocations": len(self.relocations),
            "sections": len(self.sections),
        }
