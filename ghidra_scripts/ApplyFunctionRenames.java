// Apply user-defined function names by address.
//@category PS1

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class ApplyFunctionRenames extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length == 0 || (args.length % 2) != 0) {
			throw new IllegalArgumentException(
				"ApplyFunctionRenames.java requires pairs of: <function-address> <new-name>");
		}

		for (int i = 0; i < args.length; i += 2) {
			Address address = toAddr(args[i]);
			String newName = args[i + 1];
			Function function = getFunctionAt(address);
			if (function == null) {
				function = getFunctionContaining(address);
			}
			if (function == null) {
				printerr("No function found at " + args[i] + " for name " + newName);
				continue;
			}

			String oldName = function.getName();
			if (oldName.equals(newName)) {
				println("Keeping " + newName + " @ " + function.getEntryPoint());
				continue;
			}

			function.setName(newName, SourceType.USER_DEFINED);
			println("Renamed " + oldName + " -> " + newName + " @ " + function.getEntryPoint());
		}
	}
}