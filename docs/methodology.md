# Decompiling PS1 Games With This Repo

This repo now contains a reusable PS1 pipeline that:

1. Detects common PS1 image layouts (`.cue` + raw `.bin`, raw `2352`, and plain `2048` `.iso`)
2. Parses the visible ISO9660 filesystem
3. Detects visible `PS-X EXE` files automatically
4. Extracts those executables plus `SYSTEM.CNF`
5. Builds a Ghidra project headlessly using `ghidra_psx_ldr` when available, with raw-binary import as fallback

## One-command pipeline

Run:

```bash
python3 tools/ps1_ghidra_pipeline.py \
  "/path/to/game.cue"
```

Default outputs go next to the disc image:

- `extracted/`: extracted files plus `manifest.json`
- `analysis/ghidra/`: Ghidra project, import logs, and `ps1_pipeline_report.json`

For Einhander specifically, this discovers and imports:

- `SCUS_942.43;1` as the boot executable from `SYSTEM.CNF`
- `SYS.EXE;1` as a second visible `PS-X EXE`

If `ghidra_psx_ldr` is installed, the pipeline now prefers the PSX loader automatically.
If it is not installed, the pipeline falls back to raw-binary import with the PS-X EXE header values.

To install the extension from a downloaded release zip:

```bash
./tools/install_ghidra_psx_ldr.sh \
  "/path/to/ghidra_12.0.4_PUBLIC_20260310_ghidra_psx_ldr.zip"
```

## Manual extraction only

If you only want the extraction/manifest phase:

```bash
python3 tools/extract_psx_executables.py \
  "/path/to/game.cue" \
  --extract-defaults
```

That writes:

- `SYSTEM.CNF`
- every visible `PS-X EXE`
- a `manifest.json` with file LBAs, sizes, layout info, and PS-X EXE header fields

## Ghidra launch helper

Homebrew Ghidra often needs an explicit `JAVA_HOME`. Use this wrapper instead of configuring the system globally:

```bash
./tools/run_ghidra.sh
```

Then open the generated `.gpr` project from the `analysis/ghidra` directory.

## Reverse-engineering survey reports

To dump a first-pass function list and subsystem hints from an imported program:

```bash
./tools/run_psx_survey.sh \
  "/path/to/analysis/ghidra" \
  "Game_PS1" \
  "SCUS_123.45"
```

That writes:

- `<program>.summary.txt`
- `<program>.functions.tsv`
- `<program>.subsystems.txt`

under the project `reports/` directory.

## Targeted tracing and renaming

For focused reversing on known addresses, the headless scripts in `ghidra_scripts/` can dump traces, callsites, references, and batch renames.

Trace one or more functions with callers, callees, string refs, and decompiled output:

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \
  "/path/to/analysis/ghidra" "Game_PS1" \
  -process "SYS.EXE" \
  -readOnly -noanalysis \
  -scriptPath "$(pwd)/ghidra_scripts" \
  -postScript TracePsxFunctions.java \
  "/path/to/output.trace.txt" 80043e80 80043f2c
```

Apply evidence-based function names back into the Ghidra project:

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \
  "/path/to/analysis/ghidra" "Game_PS1" \
  -process "SYS.EXE" \
  -noanalysis \
  -scriptPath "$(pwd)/ghidra_scripts" \
  -postScript ApplyFunctionRenames.java \
  80043e80 IndexStageStrFiles \
  80043f2c IndexMovieStrFiles
```

## What the headless import does

The generic fallback path does not require `ghidra_psx_ldr`.

For each discovered `PS-X EXE`, the pipeline imports it into Ghidra as:

- loader: `BinaryLoader`
- processor: `MIPS:LE:32:default`
- file offset: `0x800` to skip the PS-X EXE header
- base address: value from the PS-X EXE header
- length: payload size from the PS-X EXE header

Before analysis, a small Java GhidraScript seeds the executable entry point so auto-analysis starts from the real initial PC.

## Einhander values confirmed so far

`SCUS_942.43;1`

- Entry point: `0x800155FC`
- Load address: `0x80010000`
- Payload size: `0x22000`
- Initial stack pointer: `0x801FFFF0`

`SYS.EXE;1`

- Entry point: `0x800116FC`
- Load address: `0x80010000`
- Payload size: `0x52000`
- Initial stack pointer: `0x801FFFF0`

## Plugin path

The guide you linked recommends `ghidra_psx_ldr`, and it is still useful for better PS1-specific ergonomics, PsyQ signatures, and overlay work.

This repo's pipeline is the fallback that works today without requiring that extension. If you install the plugin later, you can keep using the extracted files and manifest from this workflow.

## Packed runtime code

Static import only gets you the visible executables. Games often load more code from packed files at runtime.

Einhander exposes these visible top-level resource files:

- `BININDEX.BIN`
- `BINPACK0.BIN` through `BINPACK5.BIN`
- stage/movie `.STR` files

If a target game uses overlays or packed code, import the visible executables first, then correlate packed-file blobs with runtime addresses through static descriptor analysis or your own validation workflow.

For Einhander, the current static map in [docs/einhander-engine-map.md](docs/einhander-engine-map.md) already ties several external runtime targets to `BININDEX.BIN` and `BINPACK*.BIN` descriptor chains.

Key examples already recovered:

- `0x80090258` and `0x800903B0` sit inside the `BINPACK1 entry 0 -> 0x8008C800` load.
- `0x801CF6F8` comes from `BINPACK0 entry 14` in family `(a1 = 0, a2 = 0)`.
- `0x801F9840` comes from `BINPACK4 entry 2` in family `(a1 = 6, a2 = 0)`.
- The `0x80190000` API family is currently best explained by family `(a1 = 1, a2 = 4)`, especially `BINPACK1 entry 23`.