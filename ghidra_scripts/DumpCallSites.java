// Dump callsites to a function with nearby instructions.
//@category PS1

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class DumpCallSites extends GhidraScript {

	private static class CallSiteRow {
		Address callAddress;
		Function function;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			throw new IllegalArgumentException(
				"DumpCallSites.java requires: <output-file> <target-address> [before-count] [after-count]");
		}

		File outFile = new File(args[0]);
		File parent = outFile.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IllegalStateException("Failed to create output directory: " + parent);
		}

		Address target = toAddr(args[1]);
		int beforeCount = args.length >= 3 ? Integer.parseInt(args[2]) : 6;
		int afterCount = args.length >= 4 ? Integer.parseInt(args[3]) : 3;

		List<CallSiteRow> callSites = new ArrayList<>();
		for (Reference reference : getReferencesTo(target)) {
			if (!reference.getReferenceType().isCall()) {
				continue;
			}
			CallSiteRow row = new CallSiteRow();
			row.callAddress = reference.getFromAddress();
			row.function = getFunctionContaining(row.callAddress);
			callSites.add(row);
		}

		callSites.sort(Comparator.comparing(row -> row.callAddress));

		try (PrintWriter out = new PrintWriter(outFile, "UTF-8")) {
			out.println("Target: " + target);
			out.println();
			for (CallSiteRow row : callSites) {
				out.println("==== call @ " + row.callAddress + " ====");
				if (row.function == null) {
					out.println("Function: NOFUNC");
				}
				else {
					out.println("Function: " + row.function.getName() + " @ " + row.function.getEntryPoint());
				}

				Instruction instruction = getInstructionAt(row.callAddress);
				Instruction cursor = instruction;
				for (int i = 0; i < beforeCount && cursor != null; i++) {
					cursor = cursor.getPrevious();
				}

				int remaining = beforeCount + afterCount + 1;
				while (cursor != null && remaining > 0) {
					String marker = cursor.getAddress().equals(row.callAddress) ? "=>" : "  ";
					out.println(marker + " " + cursor.getAddress() + " :: " + cursor);
					cursor = cursor.getNext();
					remaining--;
				}
				out.println();
			}
		}

		println("Wrote callsite dump to " + outFile.getAbsolutePath());
	}
}