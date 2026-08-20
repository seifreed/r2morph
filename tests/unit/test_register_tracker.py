"""
Unit tests for register_tracker module.
"""

from r2morph.core.register_tracker import (
    REG_8H,
    REG_8L,
    REG_16,
    REG_32,
    REG_64,
    REG_ALL,
    REG_SIZES_MAP,
    REG_WEIGHTS_MAP,
    RegTracker,
)
from tests.utils.assertions import expect

_EXPECTED_LEN_REG_WEIGHTS_MAP_RAX_2 = 2
_EXPECTED_LEN_TRACKER_GET_STORED_REGISTERS_3 = 3
_EXPECTED_LEN_WEIGHTS_5 = 5
_EXPECTED_REG_16_4 = 4
_EXPECTED_REG_32_2 = 2
_EXPECTED_REG_8H_8 = 8
_EXPECTED_REG_8L_16 = 16
_EXPECTED_TRACKER_GET_REGISTER_SIZE_AL_8 = 8
_EXPECTED_TRACKER_GET_REGISTER_SIZE_AX_16 = 16
_EXPECTED_TRACKER_GET_REGISTER_SIZE_EAX_32 = 32
_EXPECTED_TRACKER_GET_REGISTER_SIZE_RAX_64 = 64
_EXPECTED_TRACKER_GET_STACK_DEPTH_2 = 2
_EXPECTED_TRACKER_GET_STACK_DEPTH_2_2 = 2
_EXPECTED_TRACKER_GET_STACK_DEPTH_3 = 3


class TestRegTrackerInit:
    def test_init_empty(self):
        tracker = RegTracker()
        expect(tracker.get_stored_registers() == [])
        expect(tracker.get_stack_depth() == 0)

    def test_init_clear(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x90")
        expect(len(tracker.get_stored_registers()) == 1)
        tracker.clear()
        expect(tracker.get_stored_registers() == [])
        expect(tracker.get_stack_depth() == 0)


class TestStoreRestore:
    def test_store_single_register(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        expect(not ("rax" not in tracker.get_stored_registers()))
        expect(tracker.get_stack_depth() == 1)

    def test_store_multiple_registers(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        tracker.store_register("rbx", b"\x5b")
        tracker.store_register("rcx", b"\x59")
        expect(len(tracker.get_stored_registers()) == _EXPECTED_LEN_TRACKER_GET_STORED_REGISTERS_3)
        expect(tracker.get_stack_depth() == _EXPECTED_TRACKER_GET_STACK_DEPTH_3)

    def test_restore_register(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        restore_code = tracker.restore_register("rax")
        expect(restore_code == b"X")
        expect("rax" not in tracker.get_stored_registers())

    def test_restore_nonexistent(self):
        tracker = RegTracker()
        result = tracker.restore_register("rax")
        expect(not (result is not None))

    def test_is_stored(self):
        tracker = RegTracker()
        expect(not (tracker.is_stored("rax")))
        tracker.store_register("rax", b"\x58")
        expect(tracker.is_stored("rax"))

    def test_get_top_stack_register(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        tracker.store_register("rbx", b"\x5b")
        reg, code = tracker.get_top_stack_register()
        expect(reg == "rbx")
        expect(code == b"[")


class TestRegisterInfo:
    def test_get_subregisters(self):
        tracker = RegTracker()
        subregs = tracker.get_subregisters("rax")
        expect(subregs == ("eax", "ax", "ah", "al"))

    def test_get_subregisters_64bit(self):
        tracker = RegTracker()
        subregs = tracker.get_subregisters("r8")
        expect(subregs == ("r8d", "r8w", None, "r8b"))

    def test_get_register_size(self):
        tracker = RegTracker()
        expect(tracker.get_register_size("rax") == _EXPECTED_TRACKER_GET_REGISTER_SIZE_RAX_64)
        expect(tracker.get_register_size("eax") == _EXPECTED_TRACKER_GET_REGISTER_SIZE_EAX_32)
        expect(tracker.get_register_size("ax") == _EXPECTED_TRACKER_GET_REGISTER_SIZE_AX_16)
        expect(tracker.get_register_size("al") == _EXPECTED_TRACKER_GET_REGISTER_SIZE_AL_8)
        expect(tracker.get_register_size("unknown") == 0)

    def test_is_preserved_reg(self):
        tracker = RegTracker()
        expect(tracker.is_preserved_reg("rbx"))
        expect(tracker.is_preserved_reg("rbp"))
        expect(tracker.is_preserved_reg("ebx"))
        expect(not (tracker.is_preserved_reg("rax")))
        expect(not (tracker.is_preserved_reg("rcx")))

    def test_is_scratch_reg(self):
        tracker = RegTracker()
        expect(tracker.is_scratch_reg("rax"))
        expect(tracker.is_scratch_reg("rcx"))
        expect(tracker.is_scratch_reg("r10"))
        expect(not (tracker.is_scratch_reg("rbx")))
        expect(not (tracker.is_scratch_reg("rbp")))

    def test_get_compatible_registers(self):
        tracker = RegTracker()
        compat = tracker.get_compatible_registers("rax")
        expect("rax" not in compat)
        expect("rbx" in compat or "rcx" in compat)

    def test_get_register_weights(self):
        tracker = RegTracker()
        regs, weights = tracker.get_register_weights()
        expect(not ("rax" not in regs))
        expect(len(regs) == len(weights))
        expect(all(w > 0 for w in weights))


class TestRegisterConstants:
    def test_size_flags(self):
        expect(REG_64 == 1)
        expect(REG_32 == _EXPECTED_REG_32_2)
        expect(REG_16 == _EXPECTED_REG_16_4)
        expect(REG_8H == _EXPECTED_REG_8H_8)
        expect(REG_8L == _EXPECTED_REG_8L_16)
        expect(REG_ALL == REG_64 | REG_32 | REG_16 | REG_8H | REG_8L)

    def test_reg_sizes_map(self):
        expect(REG_SIZES_MAP["rax"] == REG_64)
        expect(REG_SIZES_MAP["eax"] == REG_32)
        expect(REG_SIZES_MAP["ax"] == REG_16)
        expect(REG_SIZES_MAP["al"] == REG_8L)
        expect(REG_SIZES_MAP["ah"] == REG_8H)

    def test_reg_weights_map(self):
        expect(not ("rax" not in REG_WEIGHTS_MAP))
        expect(isinstance(REG_WEIGHTS_MAP["rax"], tuple))
        expect(len(REG_WEIGHTS_MAP["rax"]) == _EXPECTED_LEN_REG_WEIGHTS_MAP_RAX_2)
        expect(isinstance(REG_WEIGHTS_MAP["rax"][0], int))
        expect(isinstance(REG_WEIGHTS_MAP["rax"][1], tuple))


class TestStackDepth:
    def test_stack_depth_increment(self):
        tracker = RegTracker()
        expect(tracker.get_stack_depth() == 0)
        tracker.store_register("rax", b"\x58")
        expect(tracker.get_stack_depth() == 1)
        tracker.store_register("rbx", b"\x5b")
        expect(tracker.get_stack_depth() == _EXPECTED_TRACKER_GET_STACK_DEPTH_2)

    def test_stack_depth_decrement(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        tracker.store_register("rbx", b"\x5b")
        expect(tracker.get_stack_depth() == _EXPECTED_TRACKER_GET_STACK_DEPTH_2_2)
        tracker.restore_register("rbx")
        expect(tracker.get_stack_depth() == 1)
        tracker.restore_register("rax")
        expect(tracker.get_stack_depth() == 0)


class TestDuplicateStore:
    def test_duplicate_store_ignored(self):
        tracker = RegTracker()
        tracker.store_register("rax", b"\x58")
        tracker.store_register("rax", b"\x90")
        expect(len(tracker.get_stored_registers()) == 1)
        expect(tracker.get_stored_registers() == ["rax"])


class TestGetSubregisterWeights:
    def test_subregister_weights(self):
        tracker = RegTracker()
        result = tracker.get_subregister_weights("rax")
        expect(result is not None)
        subregs, weights = result
        expect(not ("rax" not in subregs))
        expect(len(weights) == _EXPECTED_LEN_WEIGHTS_5)

    def test_subregister_weights_unknown_reg(self):
        tracker = RegTracker()
        result = tracker.get_subregister_weights("unknown_reg")
        expect(not (result is not None))
