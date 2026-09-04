"""Emit a bounded function-count metric from an IDA batch analysis."""

from pathlib import Path

import ida_auto
import ida_funcs
import ida_nalt
import ida_pro

ida_auto.auto_wait()
Path(f"{ida_nalt.get_input_file_path()}.function-count").write_text(str(ida_funcs.get_func_qty()), encoding="ascii")
ida_pro.qexit(0)
