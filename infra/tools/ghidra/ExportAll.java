// Fixed export for the gateway (ADR-0006). Runs once per file; all Ghidra tools then read the cached result on the host,
// so no model text ever reaches Ghidra. Reads the program only. Output is JSON, written to the path in the first script argument.
//@category sw-analyst
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class ExportAll extends GhidraScript {
    private static final int MAX_FUNCTIONS = 5000;
    private static final int MAX_INSTRUCTIONS = 4000;
    private static final int MAX_BLOCKS = 2000;
    private static final int MAX_REFS = 200000;
    private static final int MAX_DECOMPILED_CHARS = 65536;
    private static final int DECOMPILE_TIMEOUT_S = 30;
    private static final long BUDGET_MS = 8 * 60 * 1000L;   // the host kills the container at 10 minutes

    private BufferedWriter w;

    private static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20 || Character.isSurrogate(c)) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private static String a(Address x) {
        return "\"0x" + Long.toHexString(x.getOffset()) + "\"";
    }

    private static String hex(byte[] bytes) {
        StringBuilder b = new StringBuilder(bytes.length * 2);
        for (byte v : bytes) b.append(String.format("%02x", v));
        return b.toString();
    }

    @Override
    public void run() throws Exception {
        long deadline = System.currentTimeMillis() + BUDGET_MS;
        boolean truncated = false;
        try (BufferedWriter out = Files.newBufferedWriter(Paths.get(getScriptArgs()[0]), StandardCharsets.UTF_8)) {
            w = out;
            w.write("{\"program\":{\"format\":" + q(currentProgram.getExecutableFormat())
                + ",\"language\":" + q(currentProgram.getLanguageID().toString())
                + ",\"compiler\":" + q(currentProgram.getCompilerSpec().getCompilerSpecID().toString())
                + ",\"image_base\":" + a(currentProgram.getImageBase()) + "},\"functions\":[");
            DecompInterface dec = new DecompInterface();
            dec.openProgram(currentProgram);
            BasicBlockModel model = new BasicBlockModel(currentProgram);
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            int n = 0;
            boolean decompile = true;
            while (it.hasNext()) {
                if (n >= MAX_FUNCTIONS) { truncated = true; break; }
                Function f = it.next();
                if (decompile && System.currentTimeMillis() > deadline) { decompile = false; truncated = true; }
                if (n++ > 0) w.write(",");
                writeFunction(f, dec, model, decompile);
            }
            dec.dispose();
            w.write("],\"refs\":[");
            truncated |= writeRefs();
            w.write("],\"truncated\":" + truncated + "}");
        }
    }

    private void writeFunction(Function f, DecompInterface dec, BasicBlockModel model, boolean decompile) throws Exception {
        w.write("{\"name\":" + q(f.getName(true)) + ",\"entry\":" + a(f.getEntryPoint())
            + ",\"start\":" + a(f.getBody().getMinAddress()) + ",\"end\":" + a(f.getBody().getMaxAddress())
            + ",\"size\":" + f.getBody().getNumAddresses() + ",\"thunk\":" + f.isThunk()
            + ",\"signature\":" + q(f.getSignature().getPrototypeString()) + ",\"disasm\":[");
        InstructionIterator ins = currentProgram.getListing().getInstructions(f.getBody(), true);
        int i = 0;
        boolean cut = false;
        while (ins.hasNext()) {
            if (i >= MAX_INSTRUCTIONS) { cut = true; break; }
            Instruction x = ins.next();
            if (i++ > 0) w.write(",");
            w.write("[" + a(x.getAddress()) + "," + q(hex(x.getBytes())) + "," + q(x.toString()) + "]");
        }
        w.write("],\"disasm_truncated\":" + cut + ",\"blocks\":[");
        CodeBlockIterator blocks = model.getCodeBlocksContaining(f.getBody(), monitor);
        int b = 0;
        while (blocks.hasNext() && b < MAX_BLOCKS) {
            CodeBlock block = blocks.next();
            if (b++ > 0) w.write(",");
            w.write("{\"start\":" + a(block.getMinAddress()) + ",\"end\":" + a(block.getMaxAddress()) + ",\"succ\":[");
            CodeBlockReferenceIterator dst = block.getDestinations(monitor);
            int d = 0;
            while (dst.hasNext()) {
                CodeBlockReference r = dst.next();
                if (d++ > 0) w.write(",");
                w.write("[" + a(r.getDestinationAddress()) + "," + q(r.getFlowType().getName()) + "]");
            }
            w.write("]}");
        }
        boolean blocksCut = blocks.hasNext();
        String code = null;
        if (decompile && !f.isThunk()) {
            DecompileResults res = dec.decompileFunction(f, DECOMPILE_TIMEOUT_S, monitor);
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                code = res.getDecompiledFunction().getC();
                if (code.length() > MAX_DECOMPILED_CHARS) code = code.substring(0, MAX_DECOMPILED_CHARS) + "\n/* truncated */";
            }
        }
        w.write("],\"blocks_truncated\":" + blocksCut + ",\"decompiled\":" + q(code) + "}");
    }

    private boolean writeRefs() throws Exception {
        ReferenceManager rm = currentProgram.getReferenceManager();
        AddressIterator src = rm.getReferenceSourceIterator(currentProgram.getMemory(), true);
        int n = 0;
        while (src.hasNext()) {
            Address from = src.next();
            for (Reference r : rm.getReferencesFrom(from)) {
                Address to = r.getToAddress();
                if (!to.isMemoryAddress()) continue;
                if (n >= MAX_REFS) return true;
                if (n++ > 0) w.write(",");
                w.write("[" + a(from) + "," + a(to) + "," + q(r.getReferenceType().getName()) + "]");
            }
        }
        return false;
    }
}
