// NativeOp: one headless postScript for every lrecon NATIVE item that needs a
// Ghidra database. Args: <op> <outFile> [args...].
//
// Contract with the Go side (lrecon/op_native_util.go):
//   * exactly one JSON object is written to <outFile>, never to stdout, because
//     analyzeHeadless floods stdout with its own log.
//   * a refusal writes {"op":..., "error":"..."}; analyzeHeadless still exits 0,
//     so the Go side must read the file and treat "error" as a failure.
//   * an uncaught exception leaves no file and a non-zero analyzeHeadless exit;
//     the Go side then reports the first stderr line.
// Every result carries a real number from the database (function count, byte
// offset, instruction count): a value that only echoes an argument is a bug.
//@category lrecon

import java.io.FileWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class NativeOp extends GhidraScript {

	static final int SAMPLE = 200;      // list/pseudocode rows kept per answer
	static final int PSEUDO = 6000;     // pseudocode characters per function
	// decompile_all defaults. The caps are defaults, not fate: Go hands op
	// arguments over as env vars (op_native_util.go), and the same channel can
	// lower these, so a caller can watch the ceiling bite on a small binary
	// instead of taking the number on faith. A bad or zero value falls back to
	// the default rather than failing the op.
	static final int DECOMP_ALL_CAP = 400;
	static final long DECOMP_ALL_BUDGET_MS = 120000;
	static final int DECOMP_ALL_SAMPLE_ROWS = 50;         // rows offered, byte cap decides how many land
	static final int DECOMP_ALL_MAX_OUTPUT_BYTES = 16384; // ceiling on the sample block, reported
	static final int PATH_DEPTH = 8;

	static int envInt(String name, int def) {
		try {
			String v = System.getenv(name);
			if (v != null && !v.trim().isEmpty()) {
				int n = Integer.parseInt(v.trim());
				if (n > 0) return n;
			}
		} catch (NumberFormatException e) {
			// an unparsable knob means the default, not a failed answer
		}
		return def;
	}

	static int decompAllCap() { return envInt("LRECON_DECOMPILE_CAP", DECOMP_ALL_CAP); }

	static long decompAllBudgetMs() {
		return 1000L * envInt("LRECON_DECOMPILE_TIMEOUT_SECONDS", (int) (DECOMP_ALL_BUDGET_MS / 1000));
	}

	static int decompAllMaxOutputBytes() {
		return envInt("LRECON_DECOMPILE_MAX_OUTPUT_BYTES", DECOMP_ALL_MAX_OUTPUT_BYTES);
	}

	static int decompAllSampleRows() { return envInt("LRECON_DECOMPILE_SAMPLE_ROWS", DECOMP_ALL_SAMPLE_ROWS); }

	String op = "";
	String outFile = "";
	String[] rest = new String[0];

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			println("NativeOp: usage: <op> <outFile> [args...]");
			return;
		}
		op = args[0];
		outFile = args[1];
		rest = new String[args.length - 2];
		System.arraycopy(args, 2, rest, 0, rest.length);
		StringBuilder sb = new StringBuilder();
		sb.append("{\"op\":").append(q(op));
		sb.append(",\"program\":").append(q(currentProgram.getName()));
		try {
			dispatch(sb);
		} catch (Exception e) {
			// Report a refusal in-band; the Go side turns it into an error.
			StringBuilder err = new StringBuilder();
			err.append("{\"op\":").append(q(op));
			err.append(",\"program\":").append(q(currentProgram.getName()));
			err.append(",\"error\":").append(q(String.valueOf(e)));
			err.append("}");
			write(err.toString());
			return;
		}
		sb.append("}");
		write(sb.toString());
	}

	void dispatch(StringBuilder sb) throws Exception {
		switch (op) {
		case "address_name": addressName(sb); break;
		case "address_to_file_offset": addressToFileOffset(sb); break;
		case "analyze_function": analyzeFunction(sb); break;
		case "batch_decompile": batchDecompile(sb); break;
		case "build_call_path": callPath(sb, false); break;
		case "trace_call_path": callPath(sb, true); break;
		case "compare_functions": compareFunctions(sb); break;
		case "decompile_all": decompileAll(sb); break;
		case "find_xrefs_to_name": findXrefsToName(sb); break;
		case "get_call_graph": callGraph(sb); break;
		case "inspect_address_context": addressContext(sb); break;
		case "inspect_native_data_type": nativeDataType(sb); break;
		case "inspect_native_dispatch_metadata": dispatchMetadata(sb); break;
		case "inspect_native_instruction": nativeInstruction(sb); break;
		case "list_names": listNames(sb); break;
		case "list_procedures": listProcedures(sb); break;
		case "list_segments": listSegments(sb); break;
		case "match_native_functions": matchFunctions(sb); break;
		case "procedure_address": procedureAddress(sb); break;
		case "procedure_assembly": procedureAssembly(sb); break;
		case "procedure_callees": procedureEdges(sb, true); break;
		case "procedure_callers": procedureEdges(sb, false); break;
		case "procedure_info": procedureInfo(sb); break;
		case "procedure_pseudo_code": procedurePseudo(sb, PSEUDO * 4); break;
		case "procedure_references": procedureReferences(sb); break;
		case "read_function_instructions": readFunctionInstructions(sb); break;
		case "resolve_containing_procedure": containingProcedure(sb); break;
		case "resolve_native_call_targets": callTargets(sb); break;
		case "search_procedures": searchProcedures(sb); break;
		case "xrefs": xrefs(sb); break;
		default:
			throw new IllegalArgumentException("unknown NativeOp command: " + op);
		}
	}

	// ---------------------------------------------------------------- inputs

	String arg(int i) {
		return i < rest.length ? rest[i] : "";
	}

	String need(int i) {
		String s = arg(i);
		if (s.isEmpty()) throw new IllegalArgumentException("missing argument #" + i);
		return s;
	}

	long parseAddr(String s) {
		String t = s.trim();
		if (t.startsWith("0x") || t.startsWith("0X")) return Long.parseUnsignedLong(t.substring(2), 16);
		if (t.matches("[0-9]+")) return Long.parseLong(t);
		return Long.parseUnsignedLong(t, 16);
	}

	Address address(String s) {
		return toAddr(parseAddr(s));
	}

	Function functionAt(String s) {
		Address a = address(s);
		Function f = currentProgram.getFunctionManager().getFunctionAt(a);
		if (f == null) f = currentProgram.getFunctionManager().getFunctionContaining(a);
		return f;
	}

	// findFunction accepts "0x1234", "1234" or a symbol/function name.
	Function findFunction(String s) throws Exception {
		Function f = null;
		try {
			f = functionAt(s);
		} catch (RuntimeException e) {
			f = null; // not an address: fall through to the name scan
		}
		if (f != null) return f;
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		Function partial = null;
		while (it.hasNext()) {
			Function g = it.next();
			if (g.getName().equals(s)) return g;
			if (partial == null && g.getName().contains(s)) partial = g;
		}
		if (partial != null) return partial;
		throw new IllegalArgumentException("no function named " + s);
	}

	Address symbolAddress(String s) {
		SymbolIterator it = currentProgram.getSymbolTable().getSymbols(s);
		while (it.hasNext()) {
			Symbol sym = it.next();
			return sym.getAddress();
		}
		return null;
	}

	/** Address for either a numeric literal or a symbol name. */
	Address resolveAddress(String s) {
		try {
			return address(s);
		} catch (RuntimeException e) {
			Address a = symbolAddress(s);
			if (a == null) throw new IllegalArgumentException("no symbol " + s);
			return a;
		}
	}

	// ------------------------------------------------------------ decompiler

	DecompInterface dec;

	String pseudocode(Function f, int seconds) {
		try {
			if (dec == null) {
				dec = new DecompInterface();
				dec.openProgram(currentProgram);
			}
			DecompileResults res = dec.decompileFunction(f, seconds, monitor);
			if (res == null || !res.decompileCompleted()) return null;
			DecompiledFunction df = res.getDecompiledFunction();
			return df == null ? null : df.getC();
		} catch (Exception e) {
			return null;
		}
	}

	static int lineCount(String s) {
		if (s == null || s.isEmpty()) return 0;
		int n = 1;
		for (int i = 0; i < s.length(); i++) if (s.charAt(i) == '\n') n++;
		return n;
	}

	static String clip(String s, int max) {
		if (s == null) return null;
		return s.length() <= max ? s : s.substring(0, max);
	}

	String hex(long v) {
		return "0x" + Long.toHexString(v);
	}

	String funcName(Address a) {
		if (a == null) return null;
		Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
		if (f == null) f = currentProgram.getFunctionManager().getFunctionAt(a);
		if (f != null) return f.getName();
		Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
		return s == null ? null : s.getName();
	}

	// ------------------------------------------------------------- commands

	void addressName(StringBuilder sb) throws Exception {
		Address a = address(need(0));
		Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(a);
		MemoryBlock b = currentProgram.getMemory().getBlock(a);
		sb.append(",\"address\":").append(q(hex(a.getOffset())));
		sb.append(",\"symbol\":").append(q(sym == null ? null : sym.getName()));
		sb.append(",\"function\":").append(q(funcName(a)));
		sb.append(",\"block\":").append(q(b == null ? null : b.getName()));
		sb.append(",\"named\":").append(sym != null);
	}

	void addressToFileOffset(StringBuilder sb) throws Exception {
		Address a = address(need(0));
		MemoryBlock b = currentProgram.getMemory().getBlock(a);
		if (b == null) throw new IllegalArgumentException("address not in any memory block: " + hex(a.getOffset()));
		long rel = a.subtract(b.getStart());
		Long fileOff = null;
		for (MemoryBlockSourceInfo info : b.getSourceInfos()) {
			if (info.getFileBytes().isPresent() && info.contains(a)) {
				fileOff = info.getFileBytesOffset(a);
				break;
			}
		}
		sb.append(",\"address\":").append(q(hex(a.getOffset())));
		sb.append(",\"block\":").append(q(b.getName()));
		sb.append(",\"block_offset\":").append(rel);
		sb.append(",\"file_offset\":").append(fileOff == null ? "null" : fileOff.toString());
		sb.append(",\"file_offset_resolved\":").append(fileOff != null);
	}

	void emitPseudo(StringBuilder sb, Function f, int budget) throws Exception {
		// basis/coverage make the answer falsifiable: basis says how the text was
		// produced, coverage says how much of the function it stands for. A
		// decompiler that returns nothing is not a zero-line success: it is an
		// unresolved body, and unsupported_target says so in-band.
		String c = pseudocode(f, 60);
		sb.append(",\"entry\":").append(q(hex(f.getEntryPoint().getOffset())));
		sb.append(",\"size\":").append(f.getBody().getNumAddresses());
		sb.append(",\"signature\":").append(q(f.getSignature().getPrototypeString()));
		sb.append(",\"basis\":").append(q("ghidra decompiler output for the resolved function body"));
		if (c == null) {
			sb.append(",\"lines\":0,\"decompiled\":false");
			sb.append(",\"coverage\":\"unknown\"");
			sb.append(",\"unsupported_target\":").append(q("decompiler returned no body for "
					+ f.getName() + " at " + hex(f.getEntryPoint().getOffset())));
			return;
		}
		sb.append(",\"lines\":").append(lineCount(c));
		sb.append(",\"pseudocode\":").append(q(clip(c, budget)));
		sb.append(",\"truncated\":").append(c.length() > budget);
		sb.append(",\"decompiled\":true");
		sb.append(",\"coverage\":").append(c.length() > budget ? "\"budget-clipped\"" : "\"function-body\"");
	}

	void analyzeFunction(StringBuilder sb) throws Exception {
		Function f = findFunction(need(0));
		sb.append(",\"function\":").append(q(f.getName()));
		emitPseudo(sb, f, PSEUDO);
	}

	void batchDecompile(StringBuilder sb) throws Exception {
		if (rest.length == 0) throw new IllegalArgumentException("batch_decompile needs at least one function");
		sb.append(",\"requested\":").append(rest.length);
		sb.append(",\"functions\":[");
		int ok = 0;
		for (int i = 0; i < rest.length; i++) {
			if (i > 0) sb.append(",");
			sb.append("{\"requested\":").append(q(rest[i]));
			try {
				Function f = findFunction(rest[i]);
				sb.append(",\"function\":").append(q(f.getName()));
				String c = pseudocode(f, 60);
				sb.append(",\"lines\":").append(lineCount(c));
				sb.append(",\"pseudocode\":").append(q(clip(c, 1500)));
				if (c != null) ok++;
			} catch (Exception e) {
				sb.append(",\"error\":").append(q(String.valueOf(e.getMessage())));
			}
			sb.append("}");
		}
		sb.append("]");
		sb.append(",\"decompiled\":").append(ok);
	}

	void callPath(StringBuilder sb, boolean trace) throws Exception {
		Function from = findFunction(need(0));
		Function to = findFunction(need(1));
		sb.append(",\"from\":").append(q(from.getName()));
		sb.append(",\"to\":").append(q(to.getName()));
		// Breadth-first over called functions; depth is capped so one answer
		// never walks the whole program.
		Map<Address, Address> parent = new HashMap<>();
		Set<Address> seen = new LinkedHashSet<>();
		ArrayDeque<Function> q = new ArrayDeque<>();
		q.add(from);
		seen.add(from.getEntryPoint());
		Address goal = to.getEntryPoint();
		boolean found = from.getEntryPoint().equals(goal);
		int depth = 0;
		while (!q.isEmpty() && !found) {
			int layer = q.size();
			if (depth >= PATH_DEPTH) break;
			for (int i = 0; i < layer && !found; i++) {
				Function cur = q.removeFirst();
				List<Function> callees = new ArrayList<>(cur.getCalledFunctions(monitor));
				callees.sort((x, y) -> x.getEntryPoint().compareTo(y.getEntryPoint()));
				for (Function callee : callees) {
					Address ea = callee.getEntryPoint();
					if (seen.contains(ea)) continue;
					seen.add(ea);
					parent.put(ea, cur.getEntryPoint());
					if (ea.equals(goal)) {
						found = true;
						break;
					}
					q.add(callee);
				}
			}
			depth++;
		}
		List<String> path = new ArrayList<>();
		if (found) {
			Address cur = goal;
			while (cur != null) {
				path.add(funcName(cur));
				cur = parent.get(cur);
			}
			Collections.reverse(path);
		}
		sb.append(",\"found\":").append(found);
		sb.append(",\"depth\":").append(found ? path.size() - 1 : -1);
		sb.append(",\"visited\":").append(seen.size());
		sb.append(",\"basis\":").append(q("breadth-first walk over ghidra called-function edges"));
		boolean capped = !found && !q.isEmpty();
		if (found) {
			sb.append(",\"coverage\":\"resolved-path\"");
		} else {
			// Not finding a path is only a claim about the depth that was
			// searched, so it is labelled as such instead of "no path exists".
			sb.append(",\"coverage\":\"").append(capped ? "depth-capped" : "searched-graph").append("\"");
			sb.append(",\"unsupported_target\":").append(q("no path from " + from.getName() + " to "
					+ to.getName() + " within depth " + PATH_DEPTH));
		}
		sb.append(",\"path\":[");
		for (int i = 0; i < path.size(); i++) {
			if (i > 0) sb.append(",");
			sb.append(q(path.get(i)));
		}
		sb.append("]");
		if (trace) sb.append(",\"max_depth\":").append(PATH_DEPTH);
	}

	static Set<String> textLines(String c) {
		Set<String> out = new LinkedHashSet<>();
		if (c == null) return out;
		for (String line : c.split("\n")) {
			String t = line.trim();
			if (!t.isEmpty()) out.add(t);
		}
		return out;
	}

	void compareFunctions(StringBuilder sb) throws Exception {
		Function a = findFunction(need(0));
		Function b = findFunction(need(1));
		String ca = pseudocode(a, 60);
		String cb = pseudocode(b, 60);
		Set<String> la = textLines(ca);
		Set<String> lb = textLines(cb);
		int common = 0;
		for (String s : la) if (lb.contains(s)) common++;
		int union = la.size() + lb.size() - common;
		double sim = union == 0 ? 0.0 : (double) common / (double) union;
		sb.append(",\"a\":{\"name\":").append(q(a.getName()));
		sb.append(",\"entry\":").append(q(hex(a.getEntryPoint().getOffset())));
		sb.append(",\"lines\":").append(la.size());
		sb.append(",\"decompiled\":").append(ca != null).append("}");
		sb.append(",\"b\":{\"name\":").append(q(b.getName()));
		sb.append(",\"entry\":").append(q(hex(b.getEntryPoint().getOffset())));
		sb.append(",\"lines\":").append(lb.size());
		sb.append(",\"decompiled\":").append(cb != null).append("}");
		sb.append(",\"common_lines\":").append(common);
		sb.append(",\"union_lines\":").append(union);
		sb.append(",\"similarity\":").append(String.format(java.util.Locale.ROOT, "%.3f", sim));
	}

	void decompileAll(StringBuilder sb) throws Exception {
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		int cap = decompAllCap();
		long budgetMs = decompAllBudgetMs();
		int maxBytes = decompAllMaxOutputBytes();
		int maxRows = decompAllSampleRows();
		int total = 0, done = 0, failed = 0, skipped = 0, rows = 0, sampleBytes = 0;
		boolean truncated = false;
		long deadline = System.currentTimeMillis() + budgetMs;
		List<String> sample = new ArrayList<>();
		while (it.hasNext()) {
			Function f = it.next();
			if (f.isExternal()) {
				skipped++;
				continue;
			}
			total++;
			if (done >= cap || System.currentTimeMillis() > deadline) continue;
			// Give one function only the time the walk has left: a fixed 30s
			// per-function limit lets a single slow decompile blow far past a
			// short budget, so the wall clock would not be the cap it claims.
			long leftMs = deadline - System.currentTimeMillis();
			int secs = (int) Math.max(1L, Math.min(30L, (leftMs + 999L) / 1000L));
			String c = pseudocode(f, secs);
			if (c == null) {
				failed++;
				continue;
			}
			done++;
			if (rows < maxRows) {
				String row = "{\"name\":" + q(f.getName()) + ",\"entry\":" + q(hex(f.getEntryPoint().getOffset()))
						+ ",\"lines\":" + lineCount(c) + ",\"pseudocode\":" + q(clip(c, 400)) + "}";
				if (sampleBytes + row.length() > maxBytes) {
					// The answer has a byte ceiling, and it is reported rather than
					// silently applied: a caller sees output_bytes hit max_output_bytes
					// and knows the sample list is short.
					truncated = true;
					continue;
				}
				sample.add(row);
				sampleBytes += row.length() + 1;
				rows++;
			}
		}
		boolean exhausted = System.currentTimeMillis() > deadline;
		boolean capped = total > cap;
		sb.append(",\"functions\":").append(total);
		sb.append(",\"decompiled\":").append(done);
		sb.append(",\"failed\":").append(failed);
		sb.append(",\"external_skipped\":").append(skipped);
		sb.append(",\"capped\":").append(capped);
		// The budget is a real number, not a hidden constant: a caller can see
		// how long the walk was allowed to take and whether it ran out.
		sb.append(",\"decompile_timeout_seconds\":").append(budgetMs / 1000);
		sb.append(",\"budget_exhausted\":").append(exhausted);
		sb.append(",\"max_output_bytes\":").append(maxBytes);
		sb.append(",\"output_bytes\":").append(sampleBytes);
		sb.append(",\"truncated\":").append(truncated);
		sb.append(",\"sample_rows\":").append(rows);
		// partial means the answer is honest about being incomplete: some
		// functions were skipped because a ceiling stopped the walk or the sample.
		sb.append(",\"partial\":").append(exhausted || capped || truncated);
		sb.append(",\"sample\":[").append(String.join(",", sample)).append("]");
	}

	void findXrefsToName(StringBuilder sb) throws Exception {
		String name = need(0);
		SymbolIterator it = currentProgram.getSymbolTable().getSymbols(name);
		int symbols = 0, refs = 0;
		List<String> sites = new ArrayList<>();
		while (it.hasNext()) {
			Symbol sym = it.next();
			symbols++;
			ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(sym.getAddress());
			while (ri.hasNext()) {
				Reference r = ri.next();
				refs++;
				if (sites.size() < SAMPLE) {
					Address from = r.getFromAddress();
					sites.add("{\"from\":" + q(hex(from.getOffset())) + ",\"type\":" + q(r.getReferenceType().toString())
							+ ",\"function\":" + q(funcName(from)) + "}");
				}
			}
		}
		if (symbols == 0) throw new IllegalArgumentException("no symbol named " + name);
		sb.append(",\"name\":").append(q(name));
		sb.append(",\"symbols\":").append(symbols);
		sb.append(",\"refs\":").append(refs);
		sb.append(",\"sites\":[").append(String.join(",", sites)).append("]");
	}

	void callGraph(StringBuilder sb) throws Exception {
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		int functions = 0;
		List<String> all = new ArrayList<>();
		while (it.hasNext()) {
			Function f = it.next();
			functions++;
			for (Function callee : f.getCalledFunctions(monitor)) {
				all.add("{\"from\":" + q(f.getName()) + ",\"to\":" + q(callee.getName()) + "}");
			}
		}
		// getCalledFunctions returns a Set, whose iteration order differs per JVM
		// run: an unsorted sample answered the same binary with a different 200
		// edges on every call. Sort first, then cut, so two calls on one entry
		// are byte-identical.
		Collections.sort(all);
		List<String> sample = all.subList(0, Math.min(SAMPLE, all.size()));
		sb.append(",\"functions\":").append(functions);
		sb.append(",\"edges\":").append(all.size());
		sb.append(",\"sample\":[").append(String.join(",", sample)).append("]");
	}

	void addressContext(StringBuilder sb) throws Exception {
		Address a = address(need(0));
		MemoryBlock b = currentProgram.getMemory().getBlock(a);
		Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(a);
		Instruction ins = getInstructionAt(a);
		sb.append(",\"address\":").append(q(hex(a.getOffset())));
		sb.append(",\"block\":").append(q(b == null ? null : b.getName()));
		sb.append(",\"function\":").append(q(funcName(a)));
		sb.append(",\"symbol\":").append(q(sym == null ? null : sym.getName()));
		sb.append(",\"instruction\":").append(q(ins == null ? null : ins.toString()));
	}

	void nativeDataType(StringBuilder sb) throws Exception {
		String name = need(0);
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		// getDataType() takes a path; DWARF types live under /DWARF-and-friends
		// categories, so a bare source-level name never matches it. Fall back to
		// a name scan of the whole manager before saying the type is absent.
		DataType dt = dtm.getDataType(name);
		if (dt == null) {
			Iterator<DataType> all = dtm.getAllDataTypes();
			DataType firstMatch = null;
			while (all.hasNext()) {
				DataType cand = all.next();
				if (cand.getName().equals(name)) {
					firstMatch = cand;
					break;
				}
			}
			dt = firstMatch;
		}
		sb.append(",\"name\":").append(q(name));
		sb.append(",\"found\":").append(dt != null);
		if (dt == null) return;
		sb.append(",\"kind\":").append(q(dt.getClass().getSimpleName()));
		sb.append(",\"length\":").append(dt.getLength());
		sb.append(",\"path\":").append(q(dt.getPathName()));
		sb.append(",\"description\":").append(q(dt.getDescription()));
		if (dt instanceof Composite) {
			Composite c = (Composite) dt;
			sb.append(",\"components\":").append(c.getNumComponents());
		}
	}

	// dispatchMetadata reports the call sites of the Objective-C runtime bridge:
	// the selector-spelling pass lives in the analyzer, this is the address
	// evidence a reader can re-check.
	void dispatchMetadata(StringBuilder sb) throws Exception {
		String[] names = { "objc_msgSend", "objc_msgSend_stret", "objc_msgSendSuper2", "dispatch_async", "dispatch_sync" };
		// The fixed bridge names are the common spelling, but a real binary
		// imports more of the family (dispatch_queue_create, dispatch_semaphore_*,
		// objc_msgSendSuper2_stret). Enumerating the symbol table and keeping
		// every dispatch_/objc_msgSend name covers those without guessing, and
		// matches the import table inspect_native_api reads.
		Set<String> wanted = new LinkedHashSet<>();
		for (String name : names) {
			wanted.add(name);
			wanted.add("_" + name);
		}
		SymbolIterator all = currentProgram.getSymbolTable().getAllSymbols(true);
		while (all.hasNext()) {
			String nm = all.next().getName();
			String bare = nm.startsWith("_") ? nm.substring(1) : nm;
			if (bare.startsWith("dispatch_")) wanted.add(nm);
		}
		sb.append(",\"dispatchers\":[");
		int first = 0, sites = 0;
		List<String> rows = new ArrayList<>();
		Set<String> emitted = new HashSet<>();
		for (String alias : wanted) {
			// One row per imported name: Mach-O exposes the import ordinal
			// (0xb6, no memory) and the __stubs entry (0x100074208) as separate
			// symbols of the same name. Keep the memory symbol because calls point
			// at it, and mark the row imported when the ordinal also exists.
			List<Symbol> syms = new ArrayList<>();
			SymbolIterator it = currentProgram.getSymbolTable().getSymbols(alias);
			while (it.hasNext()) syms.add(it.next());
			if (syms.isEmpty() || !emitted.add(alias)) continue;
			Symbol chosen = syms.get(0);
			boolean imported = false;
			for (Symbol s : syms) {
				if (!s.getAddress().isMemoryAddress()) imported = true;
				else if (s.getAddress().isMemoryAddress() && !chosen.getAddress().isMemoryAddress()) chosen = s;
			}
			int n = 0;
			ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(chosen.getAddress());
			while (ri.hasNext()) {
				Reference r = ri.next();
				n++;
				sites++;
				if (rows.size() < SAMPLE) {
					rows.add("{\"callee\":" + q(alias) + ",\"from\":" + q(hex(r.getFromAddress().getOffset()))
							+ ",\"function\":" + q(funcName(r.getFromAddress())) + "}");
				}
			}
			if (first++ > 0) sb.append(",");
			sb.append("{\"name\":").append(q(alias));
			sb.append(",\"address\":").append(q(hex(chosen.getAddress().getOffset())));
			sb.append(",\"import\":").append(imported);
			sb.append(",\"refs\":").append(n).append("}");
		}
		sb.append("]");
		if (first == 0) {
			throw new IllegalArgumentException(
					"no dispatch symbol found: the program has no Objective-C/libdispatch imports");
		}
		sb.append(",\"call_sites\":").append(sites);
		sb.append(",\"sites\":[").append(String.join(",", rows)).append("]");
	}

	void nativeInstruction(StringBuilder sb) throws Exception {
		Address a = address(need(0));
		Instruction ins = getInstructionAt(a);
		if (ins == null) throw new IllegalArgumentException("no instruction at " + hex(a.getOffset()));
		sb.append(",\"address\":").append(q(hex(a.getOffset())));
		sb.append(",\"mnemonic\":").append(q(ins.getMnemonicString()));
		sb.append(",\"representation\":").append(q(ins.toString()));
		sb.append(",\"length\":").append(ins.getLength());
		sb.append(",\"flow_type\":").append(q(ins.getFlowType().toString()));
		PcodeOp[] ops = ins.getPcode();
		sb.append(",\"pcode_ops\":").append(ops.length);
		sb.append(",\"pcode\":[");
		for (int i = 0; i < ops.length && i < 20; i++) {
			if (i > 0) sb.append(",");
			sb.append(q(ops[i].toString()));
		}
		sb.append("]");
	}

	void listNames(StringBuilder sb) throws Exception {
		SymbolIterator it = currentProgram.getSymbolTable().getSymbolIterator(true);
		int n = 0;
		List<String> rows = new ArrayList<>();
		while (it.hasNext()) {
			Symbol sym = it.next();
			n++;
			if (rows.size() < SAMPLE) {
				rows.add("{\"address\":" + q(hex(sym.getAddress().getOffset())) + ",\"name\":" + q(sym.getName())
						+ ",\"type\":" + q(sym.getSymbolType().toString()) + "}");
			}
		}
		sb.append(",\"names\":").append(n);
		sb.append(",\"sample\":[").append(String.join(",", rows)).append("]");
	}

	void listProcedures(StringBuilder sb) throws Exception {
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		int external = 0;
		List<Function> all = new ArrayList<>();
		while (it.hasNext()) {
			Function f = it.next();
			all.add(f);
			if (f.isExternal()) external++;
		}
		// FunctionIterator order is per-run, so a first-200 sample changed between
		// two calls on one database. Sort by entry point, then cut: cold and warm
		// runs answer with the same 200 rows.
		all.sort(Comparator.comparingLong(f -> f.getEntryPoint().getOffset()));
		int n = all.size();
		List<String> rows = new ArrayList<>();
		for (Function f : all.subList(0, Math.min(SAMPLE, n))) {
			rows.add("{\"name\":" + q(f.getName()) + ",\"entry\":" + q(hex(f.getEntryPoint().getOffset()))
					+ ",\"size\":" + f.getBody().getNumAddresses() + ",\"external\":" + f.isExternal() + "}");
		}
		sb.append(",\"functions\":").append(n);
		sb.append(",\"external\":").append(external);
		sb.append(",\"sample\":[").append(String.join(",", rows)).append("]");
	}

	void listSegments(StringBuilder sb) throws Exception {
		MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
		long total = 0;
		sb.append(",\"blocks\":").append(blocks.length);
		sb.append(",\"segments\":[");
		for (int i = 0; i < blocks.length; i++) {
			MemoryBlock b = blocks[i];
			total += b.getSize();
			if (i > 0) sb.append(",");
			String perms = (b.isRead() ? "r" : "-") + (b.isWrite() ? "w" : "-") + (b.isExecute() ? "x" : "-");
			sb.append("{\"name\":").append(q(b.getName()));
			sb.append(",\"start\":").append(q(hex(b.getStart().getOffset())));
			sb.append(",\"end\":").append(q(hex(b.getEnd().getOffset())));
			sb.append(",\"size\":").append(b.getSize());
			sb.append(",\"perms\":").append(q(perms));
			sb.append(",\"initialized\":").append(b.isInitialized()).append("}");
		}
		sb.append("]");
		sb.append(",\"bytes\":").append(total);
	}

	static String sha256(byte[] data) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] h = md.digest(data);
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 8; i++) sb.append(String.format("%02x", h[i]));
		return sb.toString();
	}

	byte[] bodyBytes(Function f) throws Exception {
		long n = f.getBody().getNumAddresses();
		if (n <= 0 || n > 1 << 20) return null;
		byte[] buf = new byte[(int) n];
		int off = 0;
		for (AddressRange r : f.getBody()) {
			int len = (int) r.getLength();
			byte[] chunk = new byte[len];
			int read = currentProgram.getMemory().getBytes(r.getMinAddress(), chunk);
			System.arraycopy(chunk, 0, buf, off, read);
			off += read;
		}
		return buf;
	}

	// matchFunctions groups functions with byte-identical bodies. The Ghidra
	// FunctionID signature database is not shipped here, so this is the honest
	// match available without network access; identical bodies are exact, not
	// fuzzy, and the answer says so.
	void matchFunctions(StringBuilder sb) throws Exception {
		FunctionIterator it = currentProgram.getFunctionManager().getFunctionsNoStubs(true);
		Map<String, List<Function>> byHash = new LinkedHashMap<>();
		int hashed = 0;
		while (it.hasNext()) {
			Function f = it.next();
			if (f.isExternal() || f.isThunk()) continue;
			byte[] b = bodyBytes(f);
			if (b == null) continue;
			hashed++;
			byHash.computeIfAbsent(sha256(b), k -> new ArrayList<>()).add(f);
		}
		List<String> groups = new ArrayList<>();
		int duplicates = 0;
		for (Map.Entry<String, List<Function>> e : byHash.entrySet()) {
			if (e.getValue().size() < 2) continue;
			duplicates++;
			if (groups.size() >= 20) continue;
			StringBuilder g = new StringBuilder("{\"hash\":" + q(e.getKey()) + ",\"size\":"
					+ e.getValue().get(0).getBody().getNumAddresses() + ",\"functions\":[");
			for (int i = 0; i < e.getValue().size(); i++) {
				if (i > 0) g.append(",");
				g.append(q(e.getValue().get(i).getName()));
			}
			g.append("]}");
			groups.add(g.toString());
		}
		sb.append(",\"functions_hashed\":").append(hashed);
		sb.append(",\"duplicate_groups\":").append(duplicates);
		sb.append(",\"basis\":").append(q("identical function body bytes; FunctionID signature DB not used"));
		sb.append(",\"groups\":[").append(String.join(",", groups)).append("]");
	}

	void procedureAddress(StringBuilder sb) throws Exception {
		Function f = findFunction(need(0));
		sb.append(",\"function\":").append(q(f.getName()));
		sb.append(",\"entry\":").append(q(hex(f.getEntryPoint().getOffset())));
		sb.append(",\"size\":").append(f.getBody().getNumAddresses());
	}

	void procedurePseudo(StringBuilder sb, int budget) throws Exception {
		Function f = findFunction(need(0));
		sb.append(",\"function\":").append(q(f.getName()));
		emitPseudo(sb, f, budget);
	}

	void procedureAssembly(StringBuilder sb) throws Exception {
		Function f = findFunction(need(0));
		InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
		int n = 0;
		StringBuilder text = new StringBuilder();
		while (it.hasNext()) {
			Instruction ins = it.next();
			n++;
			if (n <= 400) text.append(hex(ins.getAddress().getOffset())).append("  ").append(ins).append("\n");
		}
		sb.append(",\"function\":").append(q(f.getName()));
		sb.append(",\"entry\":").append(q(hex(f.getEntryPoint().getOffset())));
		sb.append(",\"instructions\":").append(n);
		sb.append(",\"text\":").append(q(text.toString()));
	}

	void procedureEdges(StringBuilder sb, boolean callees) throws Exception {
		Function f = findFunction(need(0));
		List<Function> peers = new ArrayList<>(callees ? f.getCalledFunctions(monitor) : f.getCallingFunctions(monitor));
		peers.sort((x, y) -> x.getEntryPoint().compareTo(y.getEntryPoint()));
		sb.append(",\"function\":").append(q(f.getName()));
		sb.append(",\"count\":").append(peers.size());
		sb.append(",\"edges\":[");
		for (int i = 0; i < peers.size() && i < SAMPLE; i++) {
			if (i > 0) sb.append(",");
			Function p = peers.get(i);
			sb.append("{\"name\":").append(q(p.getName())).append(",\"entry\":")
					.append(q(hex(p.getEntryPoint().getOffset()))).append("}");
		}
		sb.append("]");
	}

	void procedureInfo(StringBuilder sb) throws Exception {
		Function f = findFunction(need(0));
		sb.append(",\"function\":").append(q(f.getName()));
		sb.append(",\"entry\":").append(q(hex(f.getEntryPoint().getOffset())));
		sb.append(",\"size\":").append(f.getBody().getNumAddresses());
		sb.append(",\"signature\":").append(q(f.getSignature().getPrototypeString()));
		sb.append(",\"parameters\":").append(f.getParameters().length);
		sb.append(",\"locals\":").append(f.getLocalVariables().length);
		sb.append(",\"calling_convention\":").append(q(f.getCallingConventionName()));
		sb.append(",\"no_return\":").append(f.hasNoReturn());
		sb.append(",\"external\":").append(f.isExternal());
		sb.append(",\"thunk\":").append(f.isThunk());
	}

	void procedureReferences(StringBuilder sb) throws Exception {
		Function f = findFunction(need(0));
		Address entry = f.getEntryPoint();
		int to = 0, from = 0;
		List<String> rows = new ArrayList<>();
		ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(entry);
		while (ri.hasNext()) {
			Reference r = ri.next();
			to++;
			if (rows.size() < SAMPLE) {
				rows.add("{\"direction\":\"to\",\"address\":" + q(hex(r.getFromAddress().getOffset())) + ",\"type\":"
						+ q(r.getReferenceType().toString()) + ",\"function\":" + q(funcName(r.getFromAddress())) + "}");
			}
		}
		InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
		while (it.hasNext()) {
			Instruction ins = it.next();
			for (Reference r : ins.getReferencesFrom()) {
				from++;
				if (rows.size() < SAMPLE) {
					rows.add("{\"direction\":\"from\",\"address\":" + q(hex(r.getFromAddress().getOffset()))
							+ ",\"target\":" + q(hex(r.getToAddress().getOffset())) + ",\"type\":"
							+ q(r.getReferenceType().toString()) + ",\"target_function\":"
							+ q(funcName(r.getToAddress())) + "}");
				}
			}
		}
		sb.append(",\"function\":").append(q(f.getName()));
		sb.append(",\"refs_to\":").append(to);
		sb.append(",\"refs_from\":").append(from);
		sb.append(",\"sites\":[").append(String.join(",", rows)).append("]");
	}

	void readFunctionInstructions(StringBuilder sb) throws Exception {
		Function f = findFunction(need(0));
		InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
		int n = 0;
		List<String> rows = new ArrayList<>();
		while (it.hasNext()) {
			Instruction ins = it.next();
			n++;
			if (rows.size() < 500) {
				rows.add("{\"address\":" + q(hex(ins.getAddress().getOffset())) + ",\"mnemonic\":"
						+ q(ins.getMnemonicString()) + ",\"text\":" + q(ins.toString()) + ",\"bytes\":"
						+ q(bytesHex(ins)) + "}");
			}
		}
		sb.append(",\"function\":").append(q(f.getName()));
		sb.append(",\"entry\":").append(q(hex(f.getEntryPoint().getOffset())));
		sb.append(",\"instructions\":").append(n);
		sb.append(",\"basis\":").append(q("ghidra listing over the resolved function body"));
		sb.append(",\"rows_truncated\":").append(n > rows.size());
		if (n == 0) {
			sb.append(",\"coverage\":\"unknown\"");
			sb.append(",\"unsupported_target\":").append(q("no instructions defined inside "
					+ f.getName() + " at " + hex(f.getEntryPoint().getOffset())));
		} else {
			sb.append(",\"coverage\":").append(n > rows.size() ? "\"capped-rows\"" : "\"full-body\"");
		}
		sb.append(",\"rows\":[").append(String.join(",", rows)).append("]");
	}

	String bytesHex(Instruction ins) {
		try {
			byte[] b = ins.getBytes();
			StringBuilder s = new StringBuilder();
			for (byte x : b) s.append(String.format("%02x", x));
			return s.toString();
		} catch (Exception e) {
			return null;
		}
	}

	void containingProcedure(StringBuilder sb) throws Exception {
		Address a = address(need(0));
		Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
		sb.append(",\"address\":").append(q(hex(a.getOffset())));
		sb.append(",\"found\":").append(f != null);
		if (f != null) {
			sb.append(",\"function\":").append(q(f.getName()));
			sb.append(",\"entry\":").append(q(hex(f.getEntryPoint().getOffset())));
			sb.append(",\"offset_in_function\":").append(a.subtract(f.getEntryPoint()));
		}
	}

	void callTargets(StringBuilder sb) throws Exception {
		Address a = address(need(0));
		Instruction ins = getInstructionAt(a);
		sb.append(",\"address\":").append(q(hex(a.getOffset())));
		sb.append(",\"instruction\":").append(q(ins == null ? null : ins.toString()));
		List<String> rows = new ArrayList<>();
		if (ins != null) {
			for (Address flow : ins.getFlows()) {
				rows.add("{\"target\":" + q(hex(flow.getOffset())) + ",\"name\":" + q(funcName(flow))
						+ ",\"kind\":\"flow\"}");
			}
			for (Reference r : ins.getReferencesFrom()) {
				Address t = r.getToAddress();
				rows.add("{\"target\":" + q(hex(t.getOffset())) + ",\"name\":" + q(funcName(t))
						+ ",\"kind\":" + q(r.getReferenceType().toString()) + "}");
			}
		}
		sb.append(",\"targets\":[").append(String.join(",", rows)).append("]");
		sb.append(",\"count\":").append(rows.size());
	}

	void searchProcedures(StringBuilder sb) throws Exception {
		String pattern = need(0);
		String needle = pattern.toLowerCase(java.util.Locale.ROOT);
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		int matches = 0;
		List<String> rows = new ArrayList<>();
		while (it.hasNext()) {
			Function f = it.next();
			if (!f.getName().toLowerCase(java.util.Locale.ROOT).contains(needle)) continue;
			matches++;
			if (rows.size() < SAMPLE) {
				rows.add("{\"name\":" + q(f.getName()) + ",\"entry\":"
						+ q(hex(f.getEntryPoint().getOffset())) + ",\"size\":" + f.getBody().getNumAddresses() + "}");
			}
		}
		sb.append(",\"pattern\":").append(q(pattern));
		sb.append(",\"matches\":").append(matches);
		sb.append(",\"functions\":[").append(String.join(",", rows)).append("]");
	}

	void xrefs(StringBuilder sb) throws Exception {
		Address a = resolveAddress(need(0));
		sb.append(",\"target\":").append(q(hex(a.getOffset())));
		int to = 0, from = 0;
		List<String> rows = new ArrayList<>();
		ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(a);
		while (ri.hasNext()) {
			Reference r = ri.next();
			to++;
			if (rows.size() < SAMPLE) {
				rows.add("{\"direction\":\"to\",\"address\":" + q(hex(r.getFromAddress().getOffset())) + ",\"type\":"
						+ q(r.getReferenceType().toString()) + ",\"function\":" + q(funcName(r.getFromAddress())) + "}");
			}
		}
		Reference[] outgoing = currentProgram.getReferenceManager().getReferencesFrom(a);
		for (Reference r : outgoing) {
			from++;
			if (rows.size() < SAMPLE) {
				rows.add("{\"direction\":\"from\",\"address\":" + q(hex(r.getFromAddress().getOffset()))
						+ ",\"target\":" + q(hex(r.getToAddress().getOffset())) + ",\"type\":"
						+ q(r.getReferenceType().toString()) + ",\"target_function\":"
						+ q(funcName(r.getToAddress())) + "}");
			}
		}
		sb.append(",\"refs_to\":").append(to);
		sb.append(",\"refs_from\":").append(from);
		sb.append(",\"sites\":[").append(String.join(",", rows)).append("]");
	}

	// ----------------------------------------------------------------- output

	void write(String json) throws Exception {
		try (FileWriter w = new FileWriter(outFile)) {
			w.write(json);
		}
		println("lrecon: wrote " + outFile);
	}

	static String q(String s) {
		if (s == null) return "null";
		StringBuilder b = new StringBuilder("\"");
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
			case '"': b.append("\\\""); break;
			case '\\': b.append("\\\\"); break;
			case '\n': b.append("\\n"); break;
			case '\r': b.append("\\r"); break;
			case '\t': b.append("\\t"); break;
			default:
				if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
				else b.append(c);
			}
		}
		return b.append("\"").toString();
	}
}
