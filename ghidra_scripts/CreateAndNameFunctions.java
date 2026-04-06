// Create missing functions at known starts and apply user-defined names.
//@category PS1

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class CreateAndNameFunctions extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length == 0 || (args.length % 2) != 0) {
			throw new IllegalArgumentException(
				"CreateAndNameFunctions.java requires pairs of: <function-address> <new-name>");
		}

		for (int i = 0; i < args.length; i += 2) {
			Address address = toAddr(args[i]);
			String newName = args[i + 1];

			Function function = getFunctionAt(address);
			if (function == null) {
				disassemble(address);
				function = createFunction(address, newName);
			}

			if (function == null) {
				printerr("Failed to create or find function at " + address + " for name " + newName);
				continue;
			}

			function.setName(newName, SourceType.USER_DEFINED);
			println("Created/named " + newName + " @ " + function.getEntryPoint());
		}
	}
}