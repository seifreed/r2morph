"""
Code signing utilities for different platforms.
"""

import logging
import platform
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class CodeSigner:
    """
    Handles code signing for different platforms.

    macOS: Uses codesign
    Windows: Uses signtool
    Linux: Uses signing tools as needed
    """

    def __init__(self):
        """Initialize code signer."""
        self.platform = platform.system()

    def sign(self, binary_path: Path, identity: str | None = None, adhoc: bool = True) -> bool:
        """
        Sign a binary.

        Args:
            binary_path: Path to binary
            identity: Signing identity (optional)
            adhoc: Use ad-hoc signing (macOS)

        Returns:
            True if successful
        """
        if self.platform == "Darwin":
            return self._sign_macos(binary_path, identity, adhoc)
        elif self.platform == "Windows":
            return self._sign_windows(binary_path, identity)
        else:
            logger.info("Code signing not required on this platform")
            return True

    def _sign_macos(self, binary_path: Path, identity: str | None, adhoc: bool) -> bool:
        """
        Sign binary on macOS.

        Args:
            binary_path: Binary path
            identity: Code signing identity
            adhoc: Use ad-hoc signing

        Returns:
            True if successful
        """
        try:
            if adhoc:
                cmd = ["codesign", "-s", "-", "-f", str(binary_path)]
            elif identity:
                cmd = ["codesign", "-s", identity, "-f", str(binary_path)]
            else:
                logger.error("Identity required for non-adhoc signing")
                return False

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                logger.info(f"Successfully signed {binary_path.name}")
                return True
            else:
                logger.error(f"Signing failed: {result.stderr}")
                return False

        except subprocess.SubprocessError as e:
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

            cmd = [
                "signtool",
                "sign",
                "/sha1",
                identity,
                "/fd",
                "SHA256",
                "/t",
                "http://timestamp.digicert.com",
                str(binary_path),
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                logger.info(f"Successfully signed {binary_path.name}")
                return True
            else:
                logger.error(f"Signing failed: {result.stderr}")
                return False

        except subprocess.SubprocessError as e:
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
            result = subprocess.run(
                ["codesign", "-v", str(binary_path)], capture_output=True, text=True, timeout=10
            )

            return result.returncode == 0

        except subprocess.SubprocessError:
            return False

    def _verify_windows(self, binary_path: Path) -> bool:
        """Verify Windows code signature."""
        try:
            result = subprocess.run(
                ["signtool", "verify", "/pa", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )

            return result.returncode == 0

        except subprocess.SubprocessError:
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
                result = subprocess.run(
                    ["codesign", "--remove-signature", str(binary_path)],
                    capture_output=True,
                    timeout=10,
                )
                return result.returncode == 0
            except subprocess.SubprocessError:
                return False

        return True
