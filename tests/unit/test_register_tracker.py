"""
Unit tests for register_tracker module.
"""

from r2morph.analysis.register_tracker import (
    RegTracker,
    REG_64,
    REG_32,
    REG_16,
    REG_8H,
    REG_8L,
    REG_ALL,
    REG_SIZES_MAP,
    REG_WEIGHTS_MAP,
)


class TestRegTrackerInit:
    def test_init_empty(self):
        tracker = RegTracker()
        assert tracker.get_stored_registers() == []
        assert tracker.get_stack_depth() == 0

    def test_init_clear(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x90")
        assert len(tracker.get_stored_registers()) == 1
        tracker.clear()
        assert tracker.get_stored_registers() == []
        assert tracker.get_stack_depth() == 0


class TestStoreRestore:
    def test_store_single_register(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        assert "rax" in tracker.get_stored_registers()
        assert tracker.get_stack_depth() == 1

    def test_store_multiple_registers(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        tracker.store_register("rbx", b"\x5b")
        tracker.store_register("rcx", b"\x59")
        assert len(tracker.get_stored_registers()) == 3
        assert tracker.get_stack_depth() == 3

    def test_restore_register(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        restore_code = tracker.restore_register("rax")
        assert restore_code == b"\x58"
        assert "rax" not in tracker.get_stored_registers()

    def test_restore_nonexistent(self):
        tracker = RegTracker()
        result = tracker.restore_register("rax")
        assert result is None

    def test_is_stored(self):
        tracker = RegTracker()
        assert not tracker.is_stored("rax")
        tracker.store_register("rax", b"\x58")
        assert tracker.is_stored("rax")

    def test_get_top_stack_register(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        tracker.store_register("rbx", b"\x5b")
        reg, code = tracker.get_top_stack_register()
        assert reg == "rbx"
        assert code == b"\x5b"


class TestRegisterInfo:
    def test_get_subregisters(self):
        tracker = RegTracker()
        subregs = tracker.get_subregisters("rax")
        assert subregs == ("eax", "ax", "ah", "al")

    def test_get_subregisters_64bit(self):
        tracker = RegTracker()
        subregs = tracker.get_subregisters("r8")
        assert subregs == ("r8d", "r8w", None, "r8b")

    def test_get_register_size(self):
        tracker = RegTracker()
        assert tracker.get_register_size("rax") == 64
        assert tracker.get_register_size("eax") == 32
        assert tracker.get_register_size("ax") == 16
        assert tracker.get_register_size("al") == 8
        assert tracker.get_register_size("unknown") == 0

    def test_is_preserved_reg(self):
        tracker = RegTracker()
        assert tracker.is_preserved_reg("rbx")
        assert tracker.is_preserved_reg("rbp")
        assert tracker.is_preserved_reg("ebx")
        assert not tracker.is_preserved_reg("rax")
        assert not tracker.is_preserved_reg("rcx")

    def test_is_scratch_reg(self):
        tracker = RegTracker()
        assert tracker.is_scratch_reg("rax")
        assert tracker.is_scratch_reg("rcx")
        assert tracker.is_scratch_reg("r10")
        assert not tracker.is_scratch_reg("rbx")
        assert not tracker.is_scratch_reg("rbp")

    def test_get_compatible_registers(self):
        tracker = RegTracker()
        compat = tracker.get_compatible_registers("rax")
        assert "rax" not in compat
        assert "rbx" in compat or "rcx" in compat

    def test_get_register_weights(self):
        tracker = RegTracker()
        regs, weights = tracker.get_register_weights()
        assert "rax" in regs
        assert len(regs) == len(weights)
        assert all(w > 0 for w in weights)


class TestRegisterConstants:
    def test_size_flags(self):
        assert REG_64 == 1
        assert REG_32 == 2
        assert REG_16 == 4
        assert REG_8H == 8
        assert REG_8L == 16
        assert REG_ALL == (REG_64 | REG_32 | REG_16 | REG_8H | REG_8L)

    def test_reg_sizes_map(self):
        assert REG_SIZES_MAP["rax"] == REG_64
        assert REG_SIZES_MAP["eax"] == REG_32
        assert REG_SIZES_MAP["ax"] == REG_16
        assert REG_SIZES_MAP["al"] == REG_8L
        assert REG_SIZES_MAP["ah"] == REG_8H

    def test_reg_weights_map(self):
        assert "rax" in REG_WEIGHTS_MAP
        assert isinstance(REG_WEIGHTS_MAP["rax"], tuple)
        assert len(REG_WEIGHTS_MAP["rax"]) == 2
        assert isinstance(REG_WEIGHTS_MAP["rax"][0], int)
        assert isinstance(REG_WEIGHTS_MAP["rax"][1], tuple)


class TestStackDepth:
    def test_stack_depth_increment(self):
        tracker = RegTracker()
        assert tracker.get_stack_depth() == 0
        tracker.store_register("rax", b"\x58")
        assert tracker.get_stack_depth() == 1
        tracker.store_register("rbx", b"\x5b")
        assert tracker.get_stack_depth() == 2

    def test_stack_depth_decrement(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        tracker.store_register("rbx", b"\x5b")
        assert tracker.get_stack_depth() == 2
        tracker.restore_register("rbx")
        assert tracker.get_stack_depth() == 1
        tracker.restore_register("rax")
        assert tracker.get_stack_depth() == 0


class TestDuplicateStore:
    def test_duplicate_store_ignored(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        tracker.store_register("rax", b"\x90")
        assert len(tracker.get_stored_registers()) == 1
        assert tracker.get_stored_registers() == ["rax"]


class TestGetSubregisterWeights:
    def test_subregister_weights(self):
        tracker = RegTracker()
        result = tracker.get_subregister_weights("rax")
        assert result is not None
        subregs, weights = result
        assert "rax" in subregs
        assert len(weights) == 5

    def test_subregister_weights_unknown_reg(self):
        tracker = RegTracker()
        result = tracker.get_subregister_weights("unknown_reg")
        assert result is None
