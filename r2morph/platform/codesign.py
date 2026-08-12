"""
Code signing utilities for different platforms.
"""

import logging
import platform
import shutil
from pathlib import Path
from typing import TypedDict, Unpack

from r2morph.adapters.process import ProcessError, run_process

logger = logging.getLogger(__name__)

# RFC 3161 timestamp authority used by signtool to countersign Authenticode
# signatures so they remain valid after the signing certificate expires.
SIGNTOOL_TIMESTAMP_URL = "http://timestamp.digicert.com"


class SigningOptions(TypedDict, total=False):
    identity: str | None
    adhoc: bool
    entitlements: Path | None
    hardened: bool
    timestamp: bool


class CodeSigner:
    """
    Handles code signing for different platforms.

    macOS: Uses codesign
    Windows: Uses signtool
    Linux: Uses signing tools as needed
    """

    def __init__(self) -> None:
        """Initialize code signer."""
        self.platform = platform.system()

    def sign(
        self,
        binary_path: Path,
        **options: Unpack[SigningOptions],
    ) -> bool:
        """
        Sign a binary.

        Args:
            binary_path: Path to binary
            identity: Signing identity (optional)
            adhoc: Use ad-hoc signing (macOS)

        Returns:
            True if successful
        """
        identity = options.get("identity")
        if self.platform == "Darwin":
            return self._sign_macos(binary_path, options)
        elif self.platform == "Windows":
            return self._sign_windows(binary_path, identity)
        else:
            logger.info("Code signing not required on this platform")
            return True

    def check_signature(self, binary_path: Path) -> bool:
        """Check if a binary's signature is valid."""
        return self.verify(binary_path)

    def is_signed(self, binary_path: Path) -> bool:
        """Return True if the binary has a valid signature."""
        return self.verify(binary_path)

    def needs_signing(self, binary_path: Path) -> bool:
        """Return True if the binary should be signed for the current platform."""
        if self.platform == "Darwin":
            return not self.verify(binary_path)
        if self.platform == "Windows":
            return not self.verify(binary_path)
        return False

    def _sign_macos(
        self,
        binary_path: Path,
        options: SigningOptions,
    ) -> bool:
        """
        Sign binary on macOS.

        Args:
            binary_path: Binary path
            identity: Code signing identity
            adhoc: Use ad-hoc signing

        Returns:
            True if successful
        """
        identity = options.get("identity")
        adhoc = options.get("adhoc", True)
        try:
            if adhoc:
                cmd = ["codesign", "-s", "-", "-f", str(binary_path)]
            elif identity:
                cmd = ["codesign", "-s", identity, "-f", str(binary_path)]
            else:
                logger.error("Identity required for non-adhoc signing")
                return False
            if not options.get("timestamp", False):
                cmd.append("--timestamp=none")
            if options.get("hardened", False):
                cmd += ["--options", "runtime"]
            entitlements = options.get("entitlements")
            if entitlements:
                cmd += ["--entitlements", str(entitlements)]

            result = run_process(cmd, timeout=30)

            if result.returncode == 0:
                logger.info(f"Successfully signed {binary_path.name}")
                return True
            else:
                logger.error(f"Signing failed: {result.stderr_text}")
                return False

        except ProcessError as e:
            logger.error(f"Failed to sign binary: {e}")
            return False

    def _sign_windows(self, binary_path: Path, identity: str | None) -> bool:
        """
        Sign binary on Windows.

        Args:
            binary_path: Binary path
            identity: Certificate thumbprint or path

        Returns:
            True if successful
        """
        try:
            if not identity:
                logger.warning("No signing identity provided for Windows")
                return False

            if shutil.which("signtool") is None:
                logger.warning("signtool not available on PATH")
                return False

            cmd = [
                "signtool",
                "sign",
                "/sha1",
                identity,
                "/fd",
                "SHA256",
                "/t",
                SIGNTOOL_TIMESTAMP_URL,
                str(binary_path),
            ]

            result = run_process(cmd, timeout=60)

            if result.returncode == 0:
                logger.info(f"Successfully signed {binary_path.name}")
                return True
            else:
                logger.error(f"Signing failed: {result.stderr_text}")
                return False

        except (ProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to sign binary: {e}")
            return False

    def verify(self, binary_path: Path) -> bool:
        """
        Verify code signature.

        Args:
            binary_path: Binary to verify

        Returns:
            True if signature is valid
        """
        if self.platform == "Darwin":
            return self._verify_macos(binary_path)
        elif self.platform == "Windows":
            return self._verify_windows(binary_path)
        else:
            return True

    def _verify_macos(self, binary_path: Path) -> bool:
        """Verify macOS code signature."""
        try:
            result = run_process(["codesign", "--verify", "--deep", "--strict", binary_path], timeout=10)

            return result.returncode == 0

        except ProcessError:
            return False

    def _verify_windows(self, binary_path: Path) -> bool:
        """Verify Windows code signature."""
        try:
            if shutil.which("signtool") is None:
                logger.warning("signtool not available on PATH")
                return False

            result = run_process(["signtool", "verify", "/pa", binary_path], timeout=10)

            return result.returncode == 0

        except (ProcessError, FileNotFoundError):
            return False

    def remove_signature(self, binary_path: Path) -> bool:
        """
        Remove code signature.

        Args:
            binary_path: Binary path

        Returns:
            True if successful
        """
        if self.platform == "Darwin":
            try:
                result = run_process(["codesign", "--remove-signature", binary_path], timeout=10)
                return result.returncode == 0
            except ProcessError:
                return False

        return True
