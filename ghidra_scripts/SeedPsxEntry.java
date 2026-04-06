// Seed a PS1 entry point in a raw-binary import before analysis.
//@category PS1

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class SeedPsxEntry extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException("SeedPsxEntry.java requires an entry point address argument");
		}

		Address entry = toAddr(Long.decode(args[0]));
		String label = args.length > 1 ? args[1] : "entry";

		createLabel(entry, label, true);
		addEntryPoint(entry);
		disassemble(entry);
		if (getFunctionAt(entry) == null) {
			createFunction(entry, label);
		}

		println("Seeded PS1 entry point at " + entry + " as " + label);
	}
}