import ghidra.app.script.GhidraScript;

//@category Analysis
public class CountFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("R2MORPH_FUNCTION_COUNT=" + currentProgram.getName() + "=" + currentProgram.getFunctionManager().getFunctionCount());
    }
}
