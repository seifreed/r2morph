"""Emit a bounded function-count metric from an IDA batch analysis."""

import json
from pathlib import Path

import ida_auto
import ida_funcs
import ida_nalt
import ida_pro

ida_auto.auto_wait()
input_path = ida_nalt.get_input_file_path()
Path(f"{input_path}.function-count").write_text(str(ida_funcs.get_func_qty()), encoding="ascii")
decompiler = {"entrypoints": 0, "lines": 0, "bytes": 0}
try:
    import ida_hexrays
    import ida_lines

    if ida_hexrays.init_hexrays_plugin():
        for index in range(ida_funcs.get_func_qty()):
            function = ida_funcs.getn_func(index)
            if function is None:
                continue
            pseudocode = ida_hexrays.decompile_func(function)
            if pseudocode is None:
                continue
            lines = [ida_lines.tag_remove(line.line) for line in pseudocode.get_pseudocode()]
            decompiler["entrypoints"] += 1
            decompiler["lines"] += len(lines)
            decompiler["bytes"] += len("\n".join(lines).encode("utf-8"))
except (ImportError, RuntimeError, TypeError, ValueError):
    pass
Path(f"{input_path}.decompiler").write_text(json.dumps(decompiler), encoding="utf-8")
ida_pro.qexit(0)
