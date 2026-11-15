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
decompiler = {
    "status": "unavailable",
    "reason": "decompiler plugin is unavailable",
    "entrypoints": 0,
    "lines": 0,
    "bytes": 0,
    "error_count": 0,
}
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
        decompiler["status"] = "completed" if decompiler["entrypoints"] else "unavailable"
        if decompiler["entrypoints"]:
            decompiler.pop("reason")
        else:
            decompiler["reason"] = "decompiler produced no pseudocode"
    else:
        decompiler["reason"] = "decompiler plugin could not be initialized"
except ImportError:
    decompiler["reason"] = "decompiler module is unavailable"
except (RuntimeError, TypeError, ValueError) as error:
    decompiler["status"] = "partial" if decompiler["entrypoints"] else "error"
    decompiler["error_type"] = type(error).__name__
    decompiler["error_count"] = 1
    decompiler.pop("reason")
Path(f"{input_path}.decompiler").write_text(json.dumps(decompiler), encoding="utf-8")
ida_pro.qexit(0)
