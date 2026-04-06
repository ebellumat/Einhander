// Dump a disassembly range with any containing function names.
//@category PS1

import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class DumpInstructionRange extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 3) {
			throw new IllegalArgumentException(
				"DumpInstructionRange.java requires: <output-file> <start-address> <end-address>");
		}

		File outFile = new File(args[0]);
		File parent = outFile.getParentFile();
		if (parent != null && !parent.exists() && !parent.mkdirs()) {
			throw new IllegalStateException("Failed to create output directory: " + parent);
		}

		Address start = toAddr(args[1]);
		Address end = toAddr(args[2]);

		try (PrintWriter out = new PrintWriter(outFile, "UTF-8")) {
			out.println("Range: " + start + " - " + end);
			out.println();

			Instruction instruction = getInstructionAt(start);
			if (instruction == null) {
				instruction = getInstructionAfter(start);
			}

			Function currentFunction = null;
			while (instruction != null && instruction.getAddress().compareTo(end) <= 0 && !monitor.isCancelled()) {
				Function function = getFunctionContaining(instruction.getAddress());
				if (function != currentFunction) {
					currentFunction = function;
					out.println();
					if (function == null) {
						out.println("== NOFUNC ==");
					}
					else {
						out.println("== " + function.getName() + " @ " + function.getEntryPoint() + " ==");
					}
				}

				out.println(instruction.getAddress() + " :: " + instruction);
				instruction = instruction.getNext();
			}
		}

		println("Wrote instruction range to " + outFile.getAbsolutePath());
	}
}