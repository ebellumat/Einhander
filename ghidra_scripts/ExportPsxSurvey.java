// Export a first-pass survey of a PS1 program from Ghidra.
//@category PS1

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class ExportPsxSurvey extends GhidraScript {

	private static final int MAX_REFS_PER_STRING = 8;

	private static final LinkedHashMap<String, String[]> SUBSYSTEM_KEYWORDS = new LinkedHashMap<>();

	static {
		SUBSYSTEM_KEYWORDS.put("cdrom_io", new String[] { "cd", "cdl", "cdrom", "seek", "read", "sector" });
		SUBSYSTEM_KEYWORDS.put("streaming_video", new String[] { "str", "movie", "mdec", "xa", "video" });
		SUBSYSTEM_KEYWORDS.put("graphics_gpu", new String[] { "gpu", "gte", "draw", "disp", "vsync", "graph", "ot" });
		SUBSYSTEM_KEYWORDS.put("audio_spu", new String[] { "spu", "voice", "sound", "seq", "vab", "xa" });
		SUBSYSTEM_KEYWORDS.put("input_pad", new String[] { "pad", "press", "button", "analog", "mouse" });
		SUBSYSTEM_KEYWORDS.put("memory_card", new String[] { "card", "save", "load", "format", "write" });
		SUBSYSTEM_KEYWORDS.put("interrupt_dma", new String[] { "intr", "interrupt", "dma", "madr", "timeout" });
		SUBSYSTEM_KEYWORDS.put("heap_memory", new String[] { "alloc", "malloc", "free", "heap", "memory" });
		SUBSYSTEM_KEYWORDS.put("boot_runtime", new String[] { "reset", "boot", "shell", "sys", "exe" });
	}

	private static class StringHit {
		String category;
		Address address;
		String text;
		List<String> refs;
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			throw new IllegalArgumentException("ExportPsxSurvey.java requires an output directory argument");
		}

		File outDir = new File(args[0]);
		if (!outDir.exists() && !outDir.mkdirs()) {
			throw new IllegalStateException("Failed to create output directory: " + outDir);
		}

		String baseName = currentProgram.getName();
		writeSummary(new File(outDir, baseName + ".summary.txt"));
		writeFunctionList(new File(outDir, baseName + ".functions.tsv"));
		writeSubsystemReport(new File(outDir, baseName + ".subsystems.txt"));
		println("Exported survey for " + baseName + " to " + outDir.getAbsolutePath());
	}

	private void writeSummary(File outFile) throws Exception {
		try (PrintWriter out = new PrintWriter(outFile, "UTF-8")) {
			out.println("Program: " + currentProgram.getName());
			out.println("Language: " + currentProgram.getLanguage().getLanguageID());
			out.println("Compiler: " + currentProgram.getCompilerSpec().getCompilerSpecID());
			out.println("Image base: " + currentProgram.getImageBase());
			out.println("Min address: " + currentProgram.getMinAddress());
			out.println("Max address: " + currentProgram.getMaxAddress());
			out.println("Function count: " + currentProgram.getFunctionManager().getFunctionCount());
			out.println();
			out.println("Memory blocks:");
			for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
				out.printf("  %s\t%s\t%s\tR=%s W=%s X=%s%n",
					block.getName(), block.getStart(), block.getEnd(),
					Boolean.toString(block.isRead()),
					Boolean.toString(block.isWrite()),
					Boolean.toString(block.isExecute()));
			}
		}
	}

	private void writeFunctionList(File outFile) throws Exception {
		try (PrintWriter out = new PrintWriter(outFile, "UTF-8")) {
			out.println("entry_point\tname\tbody_size\tthunk");
			FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
			while (iterator.hasNext() && !monitor.isCancelled()) {
				Function function = iterator.next();
				out.printf("%s\t%s\t%d\t%s%n",
					function.getEntryPoint(),
					function.getName(),
					function.getBody().getNumAddresses(),
					Boolean.toString(function.isThunk()));
			}
		}
	}

	private void writeSubsystemReport(File outFile) throws Exception {
		Map<String, List<StringHit>> hitsByCategory = new LinkedHashMap<>();
		for (String key : SUBSYSTEM_KEYWORDS.keySet()) {
			hitsByCategory.put(key, new ArrayList<>());
		}

		Data data = getFirstData();
		while (data != null && !monitor.isCancelled()) {
			Object value = data.getValue();
			if (value instanceof String) {
				String text = sanitizeString((String) value);
				if (text.length() >= 4) {
					for (Map.Entry<String, String[]> entry : SUBSYSTEM_KEYWORDS.entrySet()) {
						if (containsKeyword(text, entry.getValue())) {
							StringHit hit = new StringHit();
							hit.category = entry.getKey();
							hit.address = data.getMinAddress();
							hit.text = text;
							hit.refs = collectReferenceFunctions(hit.address, MAX_REFS_PER_STRING);
							hitsByCategory.get(entry.getKey()).add(hit);
							break;
						}
					}
				}
			}
			data = getDataAfter(data);
		}

		try (PrintWriter out = new PrintWriter(outFile, "UTF-8")) {
			out.println("Subsystem survey for " + currentProgram.getName());
			out.println();
			for (Map.Entry<String, List<StringHit>> entry : hitsByCategory.entrySet()) {
				out.println("== " + entry.getKey() + " ==");
				List<StringHit> hits = entry.getValue();
				if (hits.isEmpty()) {
					out.println("  (no matching defined strings)");
					out.println();
					continue;
				}
				for (StringHit hit : hits) {
					out.println("  " + hit.address + " :: " + hit.text);
					if (hit.refs.isEmpty()) {
						out.println("    refs: (none)");
					}
					else {
						for (String ref : hit.refs) {
							out.println("    ref: " + ref);
						}
					}
				}
				out.println();
			}
		}
	}

	private boolean containsKeyword(String text, String[] keywords) {
		String lower = text.toLowerCase();
		for (String keyword : keywords) {
			if (lower.contains(keyword.toLowerCase())) {
				return true;
			}
		}
		return false;
	}

	private List<String> collectReferenceFunctions(Address address, int limit) {
		Set<String> refs = new LinkedHashSet<>();
		for (Reference reference : getReferencesTo(address)) {
			Address fromAddress = reference.getFromAddress();
			Function function = getFunctionContaining(fromAddress);
			if (function != null) {
				refs.add(function.getName() + " @ " + function.getEntryPoint() + " <- " + fromAddress);
			}
			else {
				refs.add("NOFUNC @ " + fromAddress);
			}
			if (refs.size() >= limit) {
				break;
			}
		}
		return new ArrayList<>(refs);
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