// Dump targeted PS1 function traces from a Ghidra program.
//@category PS1

import java.io.File;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class TracePsxFunctions extends GhidraScript {

	private static final int MAX_CALLERS = 48;
	private static final int MAX_CALLEES = 64;
	private static final int MAX_STRINGS = 32;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			throw new IllegalArgumentException(
				"TracePsxFunctions.java requires: <output-file> <function-address> [function-address ...]");
		}

		File outFile = new File(args[0]);
		File parent = outFile.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IllegalStateException("Failed to create output directory: " + parent);
		}

		DecompInterface decompiler = new DecompInterface();
		DecompileOptions options = new DecompileOptions();
		decompiler.setOptions(options);
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(false);
		decompiler.openProgram(currentProgram);

		try (PrintWriter out = new PrintWriter(outFile, "UTF-8")) {
			out.println("Program: " + currentProgram.getName());
			out.println("Language: " + currentProgram.getLanguage().getLanguageID());
			out.println();

			for (int i = 1; i < args.length; i++) {
				Address address = toAddr(args[i]);
				Function function = getFunctionAt(address);
				if (function == null) {
					function = getFunctionContaining(address);
				}
				if (function == null) {
					out.println("==== " + args[i] + " ====");
					out.println("No function found.");
					out.println();
					continue;
				}

				writeFunctionTrace(out, function, decompiler);
			}
		}
		finally {
			decompiler.dispose();
		}

		println("Wrote function trace to " + outFile.getAbsolutePath());
	}

	private void writeFunctionTrace(PrintWriter out, Function function, DecompInterface decompiler) throws Exception {
		out.println("==== " + function.getName() + " @ " + function.getEntryPoint() + " ====");
		out.println("Body size: " + function.getBody().getNumAddresses());
		out.println("Thunk: " + function.isThunk());
		out.println();

		out.println("Callers:");
		Set<String> callers = collectCallers(function);
		if (callers.isEmpty()) {
			out.println("  (none)");
		}
		else {
			for (String caller : callers) {
				out.println("  " + caller);
			}
		}
		out.println();

		out.println("Callees:");
		Set<String> callees = collectCallees(function);
		if (callees.isEmpty()) {
			out.println("  (none)");
		}
		else {
			for (String callee : callees) {
				out.println("  " + callee);
			}
		}
		out.println();

		out.println("String refs:");
		Set<String> strings = collectStrings(function);
		if (strings.isEmpty()) {
			out.println("  (none)");
		}
		else {
			for (String stringRef : strings) {
				out.println("  " + stringRef);
			}
		}
		out.println();

		out.println("Decompile:");
		DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
		if (!results.decompileCompleted() || results.getDecompiledFunction() == null) {
			out.println("  <decompile failed: " + results.getErrorMessage() + ">");
		}
		else {
			out.println(results.getDecompiledFunction().getC());
		}
		out.println();
	}

	private Set<String> collectCallers(Function function) {
		Set<String> callers = new LinkedHashSet<>();
		for (Reference reference : getReferencesTo(function.getEntryPoint())) {
			RefType type = reference.getReferenceType();
			if (!(type.isCall() || type.isJump())) {
				continue;
			}
			Address fromAddress = reference.getFromAddress();
			Function caller = getFunctionContaining(fromAddress);
			if (caller != null) {
				callers.add(caller.getName() + " @ " + caller.getEntryPoint() + " <- " + fromAddress);
			}
			else {
				callers.add("NOFUNC <- " + fromAddress);
			}
			if (callers.size() >= MAX_CALLERS) {
				break;
			}
		}
		return callers;
	}

	private Set<String> collectCallees(Function function) {
		Set<String> callees = new LinkedHashSet<>();
		Listing listing = currentProgram.getListing();
		InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
		while (iterator.hasNext() && !monitor.isCancelled()) {
			Instruction instruction = iterator.next();
			if (!instruction.getFlowType().isCall()) {
				continue;
			}
			Address[] flows = instruction.getFlows();
			if (flows == null || flows.length == 0) {
				callees.add("INDIRECT_CALL <- " + instruction.getAddress() + " :: " + instruction);
			}
			else {
				for (Address flow : flows) {
					Function callee = getFunctionAt(flow);
					if (callee == null) {
						callee = getFunctionContaining(flow);
					}
					if (callee != null) {
						callees.add(callee.getName() + " @ " + callee.getEntryPoint() + " <- " + instruction.getAddress());
					}
					else {
						callees.add("NOFUNC @ " + flow + " <- " + instruction.getAddress());
					}
					if (callees.size() >= MAX_CALLEES) {
						return callees;
					}
				}
			}
			if (callees.size() >= MAX_CALLEES) {
				break;
			}
		}
		return callees;
	}

	private Set<String> collectStrings(Function function) {
		Set<String> strings = new LinkedHashSet<>();
		Listing listing = currentProgram.getListing();
		InstructionIterator iterator = listing.getInstructions(function.getBody(), true);
		while (iterator.hasNext() && !monitor.isCancelled()) {
			Instruction instruction = iterator.next();
			for (Reference reference : instruction.getReferencesFrom()) {
				Address toAddress = reference.getToAddress();
				if (toAddress == null) {
					continue;
				}
				Data data = getDataContaining(toAddress);
				if (data == null) {
					continue;
				}
				Object value = data.getValue();
				if (!(value instanceof String)) {
					continue;
				}
				String text = sanitizeString((String) value);
				if (text.isEmpty()) {
					continue;
				}
				strings.add(data.getMinAddress() + " :: " + text + " <- " + instruction.getAddress());
				if (strings.size() >= MAX_STRINGS) {
					return strings;
				}
			}
		}
		return strings;
	}

	private String sanitizeString(String text) {
		String trimmed = text.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ').trim();
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < trimmed.length(); i++) {
			char c = trimmed.charAt(i);
			if (c >= 32 && c < 127) {
				builder.append(c);
			}
		}
		return builder.toString().replaceAll(" +", " ");
	}
}