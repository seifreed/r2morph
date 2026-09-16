import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.nio.charset.StandardCharsets;

//@category Analysis
public class CountFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("R2MORPH_FUNCTION_COUNT=" + currentProgram.getName() + "=" + currentProgram.getFunctionManager().getFunctionCount());
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int entrypoints = 0;
        int lines = 0;
        int bytes = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            try {
                DecompileResults result = decompiler.decompileFunction(function, 10, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    continue;
                }
                String text = result.getDecompiledFunction().getC();
                if (text == null || text.trim().isEmpty()) {
                    continue;
                }
                entrypoints++;
                lines += text.split("\\R", -1).length;
                bytes += text.getBytes(StandardCharsets.UTF_8).length;
            } catch (RuntimeException ignored) {
                // One unsupported function must not discard the rest of the report.
            }
        }
        decompiler.dispose();
        println("R2MORPH_DECOMPILER=" + currentProgram.getName() + "=" + entrypoints + "=" + lines + "=" + bytes);
    }
}
