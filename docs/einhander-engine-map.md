Einhander Ghidra Initial Map
Date: 2026-04-05

Scope
- Static first pass from the headless Ghidra project built from the retail disc image.
- Survey sources were the imported programs SCUS_942.43 and SYS.EXE.

Primary split
- SCUS_942.43 is a thin boot/loader executable, not the full game runtime.
- SYS.EXE appears to contain the main runtime, CD filesystem logic, stage/movie dispatch tables, UI text, and more game-facing systems.

SCUS_942.43 findings
- Entry function is named SCUS_942 at 0x800155FC.
- Program size in Ghidra survey: 241 functions.
- The string "cdrom:\SYS.EXE;1" at 0x80010000 is referenced by main at 0x80011570.
- main tears down the small boot loop and calls LoadExec("cdrom:\\SYS.EXE;1", &DAT_801FFF00, 0x1000).
- This executable also contains many PsyQ-style wrapper/debug strings for CD, GPU, SPU, DMA, and interrupt handling.
- Confirmed role: hardware/bootstrap init, then loading SYS.EXE from disc.

SCUS confirmed functions
- main at 0x80011570: boot loop that initializes pad/CD/SPU/GPU state, then calls LoadExec for SYS.EXE.
- LoadExec at 0x8001D184: BIOS trampoline used for the SYS.EXE handoff.
- FUN_80016500: CdInit failure path.
- FUN_800172FC / FUN_8001757C / FUN_80017848 / FUN_800180FC: CD sync/ready/data timeout cluster.
- FUN_8001845C / FUN_80018670: sector retry/error path for CdRead.
- FUN_80019734 and neighbors: GPU/graph init wrappers.

SYS.EXE findings
- Entry function is named SYS at 0x800116FC.
- Program size in Ghidra survey: 754 functions.
- This looks like the real runtime payload after boot handoff.
- InitSysStartupResources at 0x8001A488 performs the one-time startup pass that initializes CD/audio state, builds BINPACK metadata, and indexes stage/movie STR files.

SYS stage/movie indexing
- IndexStageStrFiles at 0x80043E80 walks the embedded `\STAGE*.STR;1` table and fills `CdlFILE` entries via CdSearchFile.
- IndexMovieStrFiles at 0x80043F2C does the same for `\MOV*.STR;1`.
- Both are called from InitSysStartupResources during SYS startup.

SYS streaming command families
- DispatchStageXaCommand31_38 at 0x800454FC handles command bytes `0x31`-`0x38` and drives stage `STAGE*.STR` seek/play/stop flow.
- SeekStageStrFile at 0x8001E588 and StartStageXaPlayback at 0x8001E2E8 are the key stage-stream helpers behind that family.
- StopStageXaPlayback at 0x8001E70C is the matching stop/teardown side of that stage XA path.
- DispatchMovieCommand41_42 at 0x800459BC handles command bytes `0x41`-`0x42` for `MOVxx.STR` playback.
- SeekMovieStrFile at 0x80022E5C resolves the movie file location, InitMoviePlaybackContext at 0x80022ED8 prepares playback state, PrimeMoviePlayback at 0x80022F70 primes the decoder path, and PumpMoviePlayback at 0x800230E8 runs the per-frame movie stream/decode state machine.
- DispatchCdControlCommand51_53 at 0x80045B50 handles low-level CD control commands.
- SeekCdLocationAndPause at 0x8002287C and PauseCdDrive at 0x80022B4C are the common low-level helpers used by both stage and movie streaming paths.

SYS engine command queue
- SubmitEngineCommand at 0x80044294 is the raw 5-byte enqueue API for the engine's scripted/event command queue. It is not gameplay-specific and not limited to opcode `0x21`; stage XA, movie, CD-control, and generic load commands all pass through this entrypoint.
- Normal commands are written into the FIFO rooted at `DAT_80081170` through `DAT_8008121C`; commands whose high nibble is `0x7` bypass the FIFO and use the immediate slot at `DAT_80081210`-`DAT_80081214`.
- DispatchImmediateEngineCommand7x at 0x80048EB0 is the static dispatcher for that immediate `0x7*` channel.
- StopEngineCommandQueueAndPauseCd at 0x800440B4 is the producer-side shutdown path that waits for in-flight work to settle, pauses the drive, and clears the read callback.
- IsEngineCommandQueueBusy at 0x800443E0 and HasQueuedEngineCommands at 0x80044428 are the queue-status helpers used before issuing new commands.
- SubmitTableDrivenEngineCommands at 0x80038788 walks packed 5-byte command streams from data tables and forwards most entries into SubmitEngineCommand. Static evidence points to this as the main table/script-fed producer behind movie and CD-control command families.
- EnterScriptedResourceMode at 0x8003895C switches the runtime into a scripted resource mode, resets the queue, and clears the render state before queued resource work resumes.
- DispatchScriptedEngineState at 0x800388B8 is the top-level state dispatcher for `DAT_80081398`. It selects one of two handler tables at `0x80056EA0` or `0x80056EC4` depending on the mode flags `DAT_8008595E` and `DAT_8008593C`, calls the selected state handler indirectly, and returns the completion flag in `DAT_80062AE0`.
- AdvanceScriptedEngineState at 0x8001C5F8 is the common helper that clears the scripted-engine substate counters (`DAT_8008139A`/`9E`/`A0`/`A2`/`BA`) and increments the top-level state index `DAT_80081398`.
- HandleStageXaCommandSequence at 0x80048594 is a higher-level stage-XA producer state machine. It can stop the current XA stream, submit follow-up engine commands, and emit `0x32` or `0x37` stage-XA commands depending on the active sequence.
- HandleMovieCommandSequence at 0x8004873C is a higher-level movie producer state machine. It emits `0x41` movie commands, waits for queue quiescence, may stop stage XA, and advances through a timed post-movie sequence.
- HandleStageXaToMovieCommandSequence at 0x800190EC is a lower-cluster mixed transition state machine. It opens with stage-XA commands `0x32` then `0x31`, can tear down XA playback, later emits movie command `0x41`, and finishes by falling back into generic `0x21` resource-load work.
- QueueFullscreenTransitionOverlay at 0x800194E8 builds the full-screen transition primitive used by the adjacent low-cluster transition path.
- HandleTransitionOverlayLoadSequence at 0x800195DC drives an overlay-backed load sequence. It can submit either default `0x21` work or immediate `0x70` work, polls helper stages, and keeps queuing the fullscreen transition overlay while the sequence settles.
- HandleCommand21Param1aSequence at 0x80019804 is a smaller producer sequence gated by `FUN_8009A3B8` that conditionally emits `0x21` with parameter `0x1A`.
- QueueSelectedScriptedPlaybackLoad at 0x80018A6C selects one slot from a per-index table at `0x80050940` onward, submits the matching `0x21` resource load, and seeds the bytes that later drive scripted playback state.
- SetupSelectedScriptedPlaybackData at 0x80018B84 loads per-slot pointers from `0x8005092C`/`0x80050930` into the runtime playback globals at `DAT_8008130C` and `DAT_80081310`, resets the playback counters, and copies more per-slot metadata such as `DAT_80081420`.
- RunSelectedScriptedPlayback at 0x80018D28 advances the recorded-input playback slot, forces `DAT_8008146C = 2` so pad state comes from the recorded stream in `FUN_800188FC`, and watches the configured playback limit from the same per-slot table.
- HandleScriptedPlaybackSkipWindowStage1 at 0x800199AC and HandleScriptedPlaybackSkipWindowStage2 at 0x80019AA0 are the two pre-playback skip-poll states in that table. Both watch pad bits through `FUN_8001D9CC`; if the player triggers the skip combo they branch directly into the exit path at state 9.
- WaitForScriptedPlaybackStartReady at 0x80019B84 is the small readiness gate between playback-data setup and the actual recorded-input playback state.
- WaitForScriptedPlaybackFadeOut at 0x80019BD0 is the audio/CD fade-out gate that runs before leaving the scripted playback slot and hands control to the next `DAT_800813BA` state once the fade path reports completion.
- HandleScriptedPlaybackSequence at 0x8001A018 is the higher-level wrapper above that slot-driven scripted-playback system. Its state 3 dispatches through the table at `0x800509DC`, whose currently recovered order is: slot load -> skip poll stage 1 -> skip poll stage 2 -> playback-data setup -> start-ready wait -> recorded-input playback -> fade-out wait -> default `0x21` load -> next-slot exit -> stop-queue default load -> skip-exit finalize.
- States 1 and 2 of HandleScriptedPlaybackSequence call unresolved code at `0x80090258` and `0x800903B0`. Both targets sit outside SYS.EXE's static loaded range (`0x80010000`-`0x80062000`), which is stronger evidence that this wrapper can hand off into runtime-loaded code rather than only static SYS.EXE logic.
- AdvanceScriptedPlaybackSlot at 0x80019C94 rotates the slot index in `DAT_80081496` modulo four after resetting the queue/runtime state. This rotating index, combined with per-slot resource and input tables, strongly suggests a scripted attract/demo loop rather than a one-off cutscene path.
- EnableScriptedPlaybackSkip at 0x8001A178 arms the `DAT_8008134E` flag that `FUN_8001DB88` later checks so pad input can break out of scripted playback. This is the strongest static evidence so far that the rotating scripted-playback slots are user-interruptible demo/attract content.
- WaitForScriptedPlaybackExit at 0x8001A13C waits for DispatchScriptedEngineState at `0x800388B8` to finish, then restores live pad input by clearing `DAT_8008146C`.
- SubmitDefaultResourceLoadCommand at 0x80019C4C and StopQueueAndSubmitDefaultResourceLoad at 0x80019D5C are the simplest hard-coded leaves for the default `0x21` resource-load path.
- FinalizeScriptedPlaybackSkipExit at 0x80019F90 is the last state in the scripted-playback skip branch. After the stop-queue/default-load path has run, it waits for queue idle and fade progression, then reinitializes the runtime and exits back through global state `DAT_80081398 = 2`.
- DispatchTwoPhaseResourceLoadSequence at 0x80019F54 is a dedicated `DAT_800813B8` substate dispatcher for a two-phase `0x21` load/reset path. Its currently named leaves are BeginTwoPhaseResourceLoadSequence at 0x80019DC8, AdvanceTwoPhaseResourceLoadSequence at 0x80019E50, FinalizeTwoPhaseResourceLoadSequence at 0x80019EA8, and CompleteTwoPhaseResourceLoadSequence at 0x80019F0C.
- HandleStopQueueThenDefaultLoadSequence at 0x8001A374 is another small producer sequence that waits for StopEngineCommandQueueAndPauseCd, resets the queue, issues a default `0x21` load, and then waits for queue drain.
- The `DAT_80081398` handler tables now have a clearer static shape. The primary table at `0x80056EA0` contains entries for EnterScriptedResourceMode, the `a2 = 1` queueing states at `0x800389A4`/`0x800389E4`, a queue-busy gate at `0x80038A78`, the follow-up scripted command producer at `0x80038AD8`, SubmitTableDrivenEngineCommands, and two timed completion states at `0x80038BE8`/`0x80038C38`. The alternate table at `0x80056EC4` is a shorter variant that skips some of those stages when `DAT_8008595E == 0` or `DAT_8008593C != 0`.
- The scripted follow-up producer at `0x80038AD8` is not a loader by itself. After `FUN_801CF6F8(2)` reports ready, it queues `0x21,0,7`, then one of the table-driven pairs `{0,0x0B}` through `{0,0x0F}` from `0x80056E8C`, and conditionally queues `0x21,1,5` when `DAT_80081376 == 1`.
- WaitForEngineCommandQueueSettle at 0x80044700 is a generic queue-drain helper used by the `0x800389E4` and `0x80038B7C` states as well as the two-phase `0x21` path. It waits for the FIFO, immediate slot, and active worker flag to go idle, then holds for roughly 30 frames before reporting completion.
- Direct traces of `0x801CF6F8` and `0x801F9840` do not decompile inside SYS.EXE: Ghidra reports both as lying in uninitialized memory blocks. That is stronger evidence that these call targets belong to runtime-loaded code/data regions rather than the static SYS.EXE image.
- The scripted-playback slot table at `0x8005092C` contains four 0x2C-byte records. Only slot 1 sets `DAT_80081420 = 1`, which is the exact flag that switches the main loop over to the external `0x801903C4`/`0x80190428`/`0x8019063C`/`0x80190654` API surface and to the state-1/state-2 handlers at `0x80090258` and `0x800903B0`.
- `QueueSelectedScriptedPlaybackLoad` at `0x80018A6C` makes that slot usage concrete: it reads `a1` from record offset `+0x14`, `a2` from `+0x18`, copies `+0x1C/+0x20/+0x24` into the playback globals, and later `SetupSelectedScriptedPlaybackData` copies `+0x28` into `DAT_80081420`. Comparing all four slot records gives initial selectors `{(0,5), (0,3), (0,8), (0,4)}` for slots 0-3 respectively, with only slot 1 setting the `+0x28` flag and therefore immediately bootstrapping the external `0x801903C4` runtime.
- Slot 1's `+0x08/+0x0C` fields are now materially explained too: `SetupSelectedScriptedPlaybackData` copies them into `DAT_80081376 = 1` and `DAT_80081D8E = 0x21`. In the first external phase, `DAT_80081D8E` acts as a row-length / iteration limit for `SubmitTableDrivenResourceCommands`, which is why slot 1 processes row-1 entries `0..32` and reaches the later `(1,4)` follow-up mini-streams.
- The `0x21` loads used by those slots index the runtime descriptor tables through `PTR_PTR_80059B64[(byte)a1][(byte)a2]`, but the actual BINPACK offset/size data comes from BININDEX-derived runtime tables under `DAT_80065080`, not from hard-coded literals in SYS.EXE.
- The four scripted-playback `0x21` entries (`a1 = 0`, `a2 = 3/4/5/8`) all resolve to the same static descriptor skeleton shape. That descriptor references a table at `0x80059D10` containing high-RAM pointers such as `0x801D4C60` and `0x801E9AC8` onward.
- Those `0x801Dxxxx`/`0x801Exxxx` pointers are not called as code. PumpBinpackLoadCommand feeds them into `FUN_8001C37C`, which enqueues them, and the per-frame runner `FUN_8001C3C8` later interprets them as image-upload command streams using `LoadImage` and `FUN_8001D294`. This separates the scripted-playback path into two external pieces: runtime-loaded data/command streams in high RAM and a smaller set of direct external code entry points at `0x80090258`/`0x800903B0` and `0x801903C4`/`0x80190428`/`0x8019063C`/`0x80190654`.
- A separate state table at `0x8005B08C` also dispatches queue-driven handlers such as `0x8004892C`, `0x80048A80`, and `0x80048C9C`. Static evidence shows this is another engine-command state machine: it emits table-driven `0x21` commands, runs helper `FUN_80047AB4`, and in one branch issues the fixed sequence `0x21,6,3 -> 0x21,6,1 -> wait -> 0x21,6,6`. This further supports the distinction between command-queue producers and the actual BINPACK/runtime consumers downstream.
- Hard-coded stage XA producers are visible in gameplay-state code around `0x8001917C`/`0x8001922C` (`0x32` and `0x31`), `0x80019024` (`0x38`), `0x800486C4` (`0x37`), and `0x80048A18` (`0x36`).
- The generic opcode `0x21` is emitted from many gameplay/UI clusters, which suggests it is the main scriptable resource-load opcode rather than a one-off cinematic path.
- A table-driven producer site at `0x80038850` forwards command bytes and parameters from data into SubmitEngineCommand, which is the strongest static explanation for how movie (`0x41`/`0x42`) and CD-control (`0x51`-`0x53`) families enter the queue without direct hard-coded `li a0,...` callsites.

SYS CD/filesystem cluster
- InitBinpackIndex at 0x80043D24 resolves `\BININDEX.BIN;1` plus the `\BINPACK*.BIN;1` set, then reads BININDEX into runtime tables.
- ResetEngineCommandQueue at 0x8004421C clears and re-arms the runtime engine command queue in `DAT_80081170`.
- PumpEngineCommandQueue at 0x80045CC8 is the per-frame dispatcher for that queue.
- PumpBinpackLoadCommand at 0x80044C98 is the BINPACK-specific worker. It uses the BININDEX-derived tables to compute sector offsets inside `BINPACKn`, then routes payloads by type into RAM, VRAM via LoadImage, or other handlers/callbacks.
- FinishBinpackLoadCommand at 0x80044B64 advances or resets queue state after each BINPACK job completes.
- PumpCdReadRequest at 0x80047134 is the lower-level asynchronous `CdRead` state machine used by the BINPACK worker.
- FUN_8004609C: CdSearchFile path with debug strings for missing directories/files.
- FUN_80046388: CD_newmedia path; parses PVD and directory entries, checks for CD001.
- FUN_80046710: CD_cachefile path; directory/file cache builder.
- FUN_80046A5C: CdRead sector error path.
- FUN_80046C70: CdRead shell-open/retry path.

SYS audio cluster
- FUN_8002E5B0: sequence loading/open failure path ("Can't Open Sequence data any more").
- FUN_8003066C: SEQ format validation/parsing path (old format / not SEQ data strings).
- FUN_8001EFBC / FUN_8001F250: SPU timeout/wait cluster.

SYS UI/text clusters
- Narrative/story text appears embedded around 0x8005A440 onward.
- Results or score UI text appears around 0x8005FC20 onward: SHOT DOWN, TOTAL, SUBTOTAL, TIMEOUT.
- DrawResultsEntry at 0x8004B398 dispatches one results-row renderer based on a row type table.
- DrawResultTimeOrTimeout at 0x8004B824 renders either `TIMEOUT` or an `MM:SS` style time value.
- DrawSignedResultValue at 0x8004B9D0 renders signed numeric result values and places plus/minus glyphs when needed.
- DrawNumberGlyphs at 0x8004BB88 and DrawGlyphString at 0x8004BE8C are the low-level sprite text helpers used by that results cluster.

Confirmed boot chain
- Boot chain is:
  1. SCUS_942.43 initializes low-level runtime and CD access.
  2. SCUS loader routine reads and transfers control to SYS.EXE.
  3. SYS.EXE owns stage/movie selection, BINPACK/BININDEX asset streaming, engine-command queueing, CD filesystem walking, audio sequence handling, and higher-level game/UI flow.

Immediate next targets
- Identify which BINPACK entry types correspond to plain RAM assets, VRAM uploads, compressed blocks, or executable overlays.
- Continue upward from the scripted-playback map into the still-weak sibling wrappers such as `0x800199AC`, `0x80019AA0`, `0x80019B84`, and `0x80019F90`, plus the unresolved external states at `0x80090258` and `0x800903B0`.
- Resolve what runtime payload owns the external scripted-playback handlers at `0x80090258` and `0x800903B0`, and whether they are loaded from BINPACK or some other overlay-like path.
- Recover the concrete BININDEX records that populate the scripted-playback descriptor skeleton and determine which payload owns the direct external code entry points versus the `0x801Dxxxx`/`0x801Exxxx` image-command streams.
- Confirm whether any BINPACK entries are ever jumped into as code, rather than treated as data/assets.

Update after ghidra_psx_ldr install
- The project was rebuilt using ghidra_psx_ldr and the PSX language instead of the raw-binary fallback.
- PsyQ Signatures resolved a large amount of low-level runtime naming, especially in SYS.EXE.

Recovered names of interest
- SCUS 0x80011570 is now named main.
- SYS 0x800116FC is now named start.
- SYS 0x80012EF4 is now named VSync.
- SYS 0x80013BB8 is now named GsInitGraph.
- SYS 0x80013C30 is now named gpu_init.
- SYS 0x800143C4 is now named gte_init.
- SYS 0x8004609C is now named CdSearchFile.
- SYS 0x80046388 is now named CD_newmedia.
- SYS 0x80046710 is now named CD_cachefile.
- SYS 0x800469BC is now named cd_read.
- SYS 0x80046A5C is now named cb_read.
- SYS 0x80046C70 is now named cd_read_retry.
- SYS 0x80046E3C is now named CdReadBreak.
- SYS 0x80046E8C is now named CdRead.
- SYS 0x80046F6C is now named CdReadSync.

What did not auto-resolve yet
- Static BININDEX/BINPACK correlation now narrows the slot-1 scripted-playback path. The only playback slot with `DAT_80081420 = 1` is slot 1 in the table at `0x8005092C`, and that slot submits `0x21` with `(a1 = 0, a2 = 3)`.
- Descriptor `(a1 = 0, a2 = 3)` is a chained BINPACK script, not a single load. Its recovered subrecords are now concrete: `BINPACK1 entry 6 -> 0x80143800`, `entry 0 -> 0x8008C800`, `entry 1 -> 0x80146000` through a mode-1 postprocess table, `entry 11` through the mode-2 VAB/SPU helper path, `BINPACK0 entry 8` through mode-2 helper 26, then `BINPACK1 entry 3 -> 0x80146000`.
- This resolves the low external family much better than before: `0x80090258` and `0x800903B0` both sit inside the `0x8008C800` window populated by `BINPACK1 entry 0`, so the current best static explanation for those handlers is the direct family-0 load to `0x8008C800`, not the audio-oriented mode-2 legs.
- The low-family `BINPACK1 entry 0` mapping is now concrete at byte level too. Inside that blob, offsets `+0x30F0`, `+0x3A58`, and `+0x3BB0` line up with `0x8008F8F0`, `0x80090258`, and `0x800903B0` respectively and all contain executable-looking MIPS sequences. The same blob also embeds direct high-family references such as `0x801903C4` and `0x80190654`, which keeps entry 0 relevant as slot-1 bootstrap material even though it is no longer the best full explanation for the final `0x80190000` executable body.
- The `type = 1, mode = 2` / `type = 2, mode = 2` loader cluster around `0x80033A10` and `0x80034CB4` is now better classified: it is a VAB/SPU-oriented streaming path that calls `SsUtGetVagAtr`, `SsVabFakeBody`, `SsVabOpenHeadSticky`, `SpuRead`, and `SpuSetTransferStartAddr`. That makes this path a poor match for the direct `0x80190000` code overlay hypothesis.
- The best current explanation for the high external family rooted at `0x80190000` is now family `(a1 = 1, a2 = 4)`, not `(a1 = 0, a2 = 3)` alone. That descriptor stages `BINPACK1 entry 21` and `entry 22` through mode 1 at `0x80190000`, then direct-loads `BINPACK1 entry 23` to the same base. Byte checks at the exact external API offsets show code-like MIPS sequences inside `entry 23` for `0x801903C4`, `0x80190428`, `0x80190468`, `0x8019063C`, and `0x80190654`, while the broader-range candidate `BINPACK1 entry 17` does not look executable at those offsets.
- The `mode = 1` helper tables used by that family strengthen the same split. The descriptor points at `0x8016741C` and `0x801676A0` inside `BINPACK1 entry 3`; those tables are arrays of `0x20`-spaced pointers into `entry 21` and `entry 22`, and the pointed records themselves carry destinations like `0x80190004`, `0x80190104`, `0x80190310`, and `0x80192054`. That makes `entry 21`/`entry 22` look like postprocessed overlay-construction tables, while `entry 23` remains the best raw executable body candidate.
- The producer path for family `(a1 = 1, a2 = 4)` is now clearer too. `SubmitTableDrivenResourceCommands` at `0x80038788` does not walk a static SYS.EXE table; it walks the runtime-loaded pointer table rooted at `DAT_800FDAC8`, which lives inside `BINPACK1 entry 0`. That function iterates `uVar5 = 0 .. DAT_80081D8E - 1`, loads a mini-script pointer from row `DAT_80081376`, and submits each 5-byte command unless the opcode's high nibble is `3` or `6`.
- Slot 1 now ties directly into that producer. `SetupSelectedScriptedPlaybackData` copies slot-1 fields `+0x08/+0x0C` into `DAT_80081376 = 1` and `DAT_80081D8E = 0x21`, so the follow-up table-driven pass processes the first 33 entries of row 1 at `0x800FD6BC`. Within that row, indices `23` and `28` point to aligned streams at `0x800FD4A0` and `0x800FD4BC` whose payload is `{0x60,...} -> {0x34,2,0x14,0} -> {0x21,1,4,8,0} -> {0x36,...}`. Because the table-driven producer skips high-nibble-`3` and high-nibble-`6` opcodes, those streams effectively contribute the missing `0x21,1,4,8,0` submissions.
- `DAT_80081D8E` is no longer just an opaque selector. Static code at `0x800489E4` resets it to `1` while incrementing `DAT_80081376`, and the external code in `BINPACK1 entry 0` then advances it through a pending-value pipeline: `0x8009B6E4` rotates `DAT_80081D94 -> DAT_80081D92`, `0x80094B30` commits `DAT_80081D92 -> DAT_80081D8E` and clears `DAT_80081D8C`, and `0x8008F764` recomputes `DAT_80081D8E` directly from the SYS.EXE table at `0x80050C38[(uint)DAT_80081376][(uint)DAT_8008147E]`. For row `DAT_80081376 = 1`, that table collapses the external state's next `DAT_80081D8E` values to the short sequence `{0,1,2,3,3,5,6,7,...}`.
- BININDEX now fixes the low external blob size too, not just its base. `BINPACK1 entry 0` is `0x016E` sectors long, so the `0x8008C800` import window is `0xB7000` bytes. Importing that raw blob at its runtime base produces direct function matches for `0x8008F764`, `0x8008F8F0`, `0x80090258`, `0x800903B0`, `0x80094B30`, and `0x8009B6E4` inside the same payload.
- `0x8008F764` is now concretely the phase-recompute helper rather than a vague table lookup. It reads `DAT_80050C38[(uint)DAT_80081376][(uint)DAT_8008147E]` into `DAT_80081D8E`, compares the resulting pair against `DAT_80081482`/`DAT_80081480`, updates a repeat counter in `DAT_80081372`, snapshots the current `(phase,row)` pair into working copies, and refreshes the active external record set through `0x800940BC`.
- The real second-stage dispatcher is `0x80094804`, not just the small rotate/commit helpers. If `DAT_80081D94 == 0xFF`, it seeds `DAT_80081D92` from the current phase record's `+0x22` halfword in `PTR_PTR_801009A8[DAT_80081376][DAT_80081D8E]`, then runs per-row helper families around `0x80099348`, `0x8009AFC0`, `0x8009B68C`, `0x8009BBF0`, `0x8009BF64`, `0x8009C144`, and `0x8009C294`. If `DAT_80081D94 != 0xFE`, it instead routes through the explicit-pending handlers `0x800993D0`, `0x8009B028`, `0x8009B6E4`, `0x8009BC80`, `0x8009BFBC`, `0x8009C1CC`, and `0x8009C31C` before committing through `0x80094B08`.
- The nontrivial `DAT_80081D94` writes are now traceable rather than inferred. The main generic writer is `0x8009C3E4`, which maps compact event ids and parameters to concrete pending states such as `{0x12,0x13,0x14,0x15,0x17,0x18,0x19,0x1A,0x1E,0x1F,0x20}`. One confirmed caller is `0x80099904`, a timed sub-sequence inside `0x800955C8`, which eventually calls `0x8009C3E4(0x0D, 0)` and thereby requests pending phase `0x1F`. The smaller per-row helpers mostly rotate `DAT_80081D94 -> DAT_80081D92`, clear `DAT_80081D94` back to `0xFF`, and optionally copy the staged vector triple `DAT_80081B98/B9C/BA0 -> DAT_80081BBC/BC0/BC4` for specific phase sets.
- The dispatcher also contains explicit row handoff logic, which confirms that `DAT_80081376` is the external row selector and not just a bootstrap id. Row 1 advances to row 2 through `0x800994C0`, row 2 advances to row 3 through `0x8009B58C` when phase `0x1F` settles, row 3 advances to row 4 through `0x8009BAF8` when phase `0x21` settles, and row 4 advances to row 5 through `0x8009BE74` when phase `0x19` settles. Each handoff resets `DAT_80081DA0/DA2`, `DAT_80081D90`, and `DAT_80081478`, and row 2 also reissues `0x36` back into the SYS.EXE engine queue.
- The resource opcodes `0x36` and `0x37` are part of the same second-stage control loop. Instead of directly queueing resource commands, they index the runtime-loaded triplet table at `DAT_800FD0A4[(uint)DAT_80081376] + DAT_80081D8E * 3`, then pass the resulting `(byte0, byte1)` pair into `FUN_8001E2E8`. That makes `DAT_80081D8E` a phase counter shared between the external mini-script table (`DAT_800FDAC8`) and the `0x36`/`0x37` control tables (`DAT_800FD0A4`).
- Comparing the playback siblings now sharpens the staging split rather than leaving the producer unresolved. All four initial scripted-playback slots still queue only family-0 descriptors `{(0,5), (0,3), (0,8), (0,4)}`, but slot 1 alone seeds the external row-1 command table that later emits the family-1 follow-up loads, including `(a1 = 1, a2 = 4)`.
- Two additional external runtime targets now have direct packed-file matches. Family `(a1 = 0, a2 = 0)` direct-loads `BINPACK0 entry 14` to `0x801CF000-0x801FC000`, and byte sampling at `0x801CF6F8` lands on a clean MIPS prologue there. Family `(a1 = 6, a2 = 0)` direct-loads `BINPACK4 entry 2` to `0x801F9800-0x801FC000`, and byte sampling at `0x801F9840` also lands on a clean MIPS prologue.
- BINPACK*.BIN is now confirmed as more than a generic resource source: at least `BINPACK0 entry 14`, `BINPACK4 entry 2`, and `BINPACK1 entry 23` contain executable-looking PSX code at the exact runtime entry offsets being called from SYS.EXE.
- The producer-side command API is now identified, but several higher-level gameplay/script callers still sit above these named sequences and remain only partially classified.
- The `0x80019000` producer cluster is no longer just a raw boundary map: the stage-XA-to-movie path, the transition-overlay load path, the `DAT_800813B8` two-phase resource-load sequence, and the rotating scripted-playback/demo-slot wrapper around `DAT_800813BA` are now named. The remaining weak spots in this area are no longer the external targets themselves, but the higher-level producer path that reaches family `(a1 = 1, a2 = 4)` and the broader gameplay state machine that chooses between these descriptor families.
- The larger gameplay/state machine above these loaders is still mostly anonymous and remains the next manual reversing target.