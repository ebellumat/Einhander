// List code references to one or more global addresses.
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

public class FindAddressRefs extends GhidraScript {

	private static class RefRow {
		String target;
		String from;
		String functionName;
		String functionEntry;
		String refType;
		String instructionText;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			throw new IllegalArgumentException(
				"FindAddressRefs.java requires: <output-file> <address> [address ...]");
		}

		File outFile = new File(args[0]);
		File parent = outFile.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IllegalStateException("Failed to create output directory: " + parent);
		}

		List<RefRow> rows = new ArrayList<>();
		for (int i = 1; i < args.length; i++) {
			Address target = toAddr(args[i]);
			for (Reference reference : getReferencesTo(target)) {
				Address fromAddress = reference.getFromAddress();
				Instruction instruction = getInstructionAt(fromAddress);
				if (instruction == null) {
					instruction = getInstructionContaining(fromAddress);
				}
				RefRow row = new RefRow();
				row.target = target.toString();
				row.from = fromAddress.toString();
				row.refType = reference.getReferenceType().toString();
				row.instructionText = instruction == null ? "<no instruction>" : instruction.toString();
				Function function = getFunctionContaining(fromAddress);
				if (function == null) {
					row.functionName = "NOFUNC";
					row.functionEntry = "-";
				}
				else {
					row.functionName = function.getName();
					row.functionEntry = function.getEntryPoint().toString();
				}
				rows.add(row);
			}
		}

		rows.sort(Comparator.comparing((RefRow row) -> row.target).thenComparing(row -> row.from));

		try (PrintWriter out = new PrintWriter(outFile, "UTF-8")) {
			out.println("target\tfrom\tfunction\tfunction_entry\tref_type\tinstruction");
			for (RefRow row : rows) {
				out.printf("%s\t%s\t%s\t%s\t%s\t%s%n",
					row.target,
					row.from,
					row.functionName,
					row.functionEntry,
					row.refType,
					row.instructionText.replace('\t', ' '));
			}
		}

		println("Wrote address refs to " + outFile.getAbsolutePath());
	}
}