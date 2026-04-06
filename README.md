# Einhander Decompilation Workspace

This repository is a clean public workspace for static reverse engineering of the PlayStation 1 release of Einhander.

It contains:

- reusable Python tooling to extract PS-X executables from disc images
- headless Ghidra automation for repeatable imports and surveys
- reusable Java Ghidra scripts for tracing, callsite dumps, reference scans, and bulk renaming
- a growing static research map for Einhander's runtime, loader flow, and packed-code descriptors

It does not contain:

- game assets
- Unity reconstruction work
- emulator RAM dumps
- generated build/cache directories
- copyrighted disc content

Bring your own legally obtained disc image.

## Repository layout

- `tools/`: extraction and Ghidra automation scripts
- `ghidra_scripts/`: headless Ghidra helpers
- `docs/methodology.md`: pipeline and workflow notes
- `docs/einhander-engine-map.md`: current reverse-engineering map and findings

## Method

The workflow is deliberately simple and reproducible:

1. Extract visible ISO9660 files and PS-X executables from a PS1 disc image.
2. Import each executable into Ghidra with either `ghidra_psx_ldr` or a raw binary fallback.
3. Seed the real PS-X entry point before analysis so references and control flow start from the correct address.
4. Export function surveys, targeted traces, callsites, and address-reference reports.
5. Correlate static command producers in `SYS.EXE` with packed runtime consumers in `BININDEX.BIN` and `BINPACK*.BIN`.
6. Record evidence-backed naming and system maps in the docs.

The emphasis in this repo is static analysis first: descriptors, dispatch tables, command queues, packed loaders, and runtime code regions are mapped by tracing executable control flow and by decoding packed-file structure.

## Quick start

Extract and import a disc image into Ghidra:

```bash
python3 tools/ps1_ghidra_pipeline.py \
  "/path/to/game.cue"
```

Run a survey over an imported program:

```bash
./tools/run_psx_survey.sh \
  "/path/to/analysis/ghidra" \
  "Game_PS1" \
  "SYS.EXE"
```

Install the PSX loader extension for Ghidra:

```bash
./tools/install_ghidra_psx_ldr.sh \
  "/path/to/ghidra_psx_ldr.zip"
```

## Current Einhander status

The current map is in [docs/einhander-engine-map.md](docs/einhander-engine-map.md).

Highlights already established:

- `SCUS_942.43` is a thin boot loader that hands off into `SYS.EXE`.
- `SYS.EXE` owns the main runtime, command queue, file indexing, and resource streaming logic.
- `SubmitEngineCommand` at `0x80044294` is a generic scripted engine/resource queue API, not a single-purpose loader.
- Several external runtime targets have been tied to specific `BINPACK` entries and descriptor families.
- The `0x80190000` family is now linked to a second-stage table-driven producer path seeded by slot 1 scripted playback.

## References

- Ghidra
- `ghidra_psx_ldr`
- PS-X EXE format
- ISO9660 filesystem layout on PlayStation discs
- PsyQ symbol/signature workflows for PS1 reversing

## Scope and legality

This repository is for reverse-engineering research and tooling. It intentionally excludes game data and generated runtime dumps. If you use it on a commercial title, keep your inputs local and do not commit extracted binaries or copyrighted assets.