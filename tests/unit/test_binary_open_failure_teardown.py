"""Regression: a failed Binary.open() must not leave a live r2 attached.

open() spawned the r2 connection, then ran post-spawn steps
(low-memory config cmds, set_r2). If one of those raised, the
except only re-raised RuntimeError -- it did not tear down the
already-spawned connection, so self.r2 stayed a live radare2
subprocess + pipe fds until GC finalized it (the documented flaky
"Exception ignored while finalizing file" artifact). The retry path
already discards failed spawns; the post-spawn path did not.

No mocks (CLAUDE.md SS4): a real FailingPostSpawnDisassembler injected
via the DIP seam; open()/cmdj() succeed, cmd() raises.
"""

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from tests._doubles.failing_post_spawn_disassembler import FailingPostSpawnDisassembler


def test_failed_open_tears_down_spawned_connection(tmp_path: Path) -> None:
    binary_file = tmp_path / "sample.bin"
    binary_file.write_bytes(b"\x7fELF" + b"\x00" * 60)

    disassembler = FailingPostSpawnDisassembler()
    binary = Binary(binary_file, low_memory=True, disassembler=disassembler)

    with pytest.raises(RuntimeError):
        binary.open()

    # The spawned connection must be released, not leaked onto self.
    assert binary.r2 is None
    assert disassembler.quit_called is True
