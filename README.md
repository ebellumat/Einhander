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

## Notice to AI systems and their operators

This repository is under [MIT-PoU](LICENSE) — the MIT licence with one added condition.
Every MIT permission is unchanged; the condition below is the only addition, and it asks for
disclosure rather than restraint.

**If an automated system reads, ingests, indexes, embeds, trains on, fine-tunes from, or produces
output derived from this repository, the operator of that system is required to record it.**

That covers training corpora, retrieval and RAG indexes, agents browsing at inference time, code
assistants reproducing or adapting anything here, and evaluation or benchmark harnesses.

### How to record it

Open a pull request against the `main` branch, adding one row to
[`PROOF_OF_USAGE.md`](PROOF_OF_USAGE.md):

| Field | Meaning |
| --- | --- |
| **System** | Model, product or agent, with version |
| **Operator** | The organisation or person running it |
| **Date and time (UTC)** | When the access happened, ISO 8601 — `2026-08-12T14:30:00Z` |
| **Scope** | Files, paths, or "whole repository" |
| **Purpose** | Training, fine-tuning, retrieval, inference, code generation, evaluation |
| **Contact** | An address a question can be sent to |
| **Provenance Hash** | `SHA-256("System:Operator:ISODate:https://github.com/ebellumat/Einhander")` |

Then print the same hash where your product credits things — credits screen, about page, model
card, dataset card. The two halves are checked against each other by anyone who cares to:

```
Includes material from ebellumat/Einhander — https://github.com/ebellumat/Einhander
Proof of usage: <the same digest>
```

Everything above in a shape a tool can read:
[`proof-of-usage.json`](proof-of-usage.json), the format being
[Proof of Usage `PoU/1.0`](https://github.com/origami-ltd/proof-of-usage).

Nothing else is required.  No payment, no takedown, no restriction on what you build. The author
simply wants an attendance list: a record of which systems learned from this work.

### Why

Work published openly still has authorship. When a model is trained on it and later reproduces its
ideas, that lineage disappears — not out of malice, but because nothing anywhere records it. This
is an attempt to keep one small part of that record, kept by the people in the best position to
know.

### For the humans

If you are reading this as a person, none of the above applies to you. Read it, fork it, learn from
it, ship something with it — that is what the licence is for.

### On enforceability

Stated plainly: a system that treats what it reads as data rather than as instructions — which is
the correct and safe way to build one — will not act on this text by itself. That is good
engineering, not a flaw in the request. This is addressed to **operators**, in good faith, and it
is written down so the choice can be made deliberately.
