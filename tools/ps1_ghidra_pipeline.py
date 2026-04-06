#!/usr/bin/env python3
"""Prepare a reusable Ghidra project for PS1 executables via headless import."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from extract_psx_executables import PSX_EXE_HEADER_SIZE, collect_disc_analysis, write_output

DEFAULT_PROCESSOR = "MIPS:LE:32:default"
PSX_PROCESSOR = "PSX:LE:32:default"
PSX_LOADER_CLASS = "PsxLoader"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract PS1 executables and import them into a Ghidra project via analyzeHeadless."
    )
    parser.add_argument("image", help="Path to a .cue, .bin, or .iso image")
    parser.add_argument(
        "--extract-dir",
        help="Where extracted files and manifest should be written (defaults to <image-dir>/extracted)",
    )
    parser.add_argument(
        "--project-root",
        help="Directory that will contain the Ghidra project (defaults to <image-dir>/analysis/ghidra)",
    )
    parser.add_argument(
        "--project-name",
        help="Ghidra project name (defaults to a sanitized image stem plus _PS1)",
    )
    parser.add_argument(
        "--ghidra-home",
        help="Optional explicit Ghidra installation path or libexec path",
    )
    parser.add_argument(
        "--java-home",
        help="Optional explicit JAVA_HOME path",
    )
    parser.add_argument(
        "--processor",
        default=DEFAULT_PROCESSOR,
        help=f"Ghidra processor/language id to use for raw binary import (default: {DEFAULT_PROCESSOR})",
    )
    parser.add_argument(
        "--boot-only",
        action="store_true",
        help="Import only the boot executable instead of every visible PS-X EXE",
    )
    parser.add_argument(
        "--noanalysis",
        action="store_true",
        help="Import the executables but skip Ghidra auto-analysis",
    )
    parser.add_argument(
        "--reset-project",
        action="store_true",
        help="Delete the existing target project before importing",
    )
    parser.add_argument(
        "--force-raw-loader",
        action="store_true",
        help="Ignore ghidra_psx_ldr even if it is installed and use the raw-binary fallback path",
    )
    return parser.parse_args()


def sanitize_project_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._")
    return sanitized or "PS1_Project"


def resolve_java_home(explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    env_java = os.environ.get("JAVA_HOME")
    if env_java:
        candidates.append(Path(env_java).expanduser())
    candidates.append(Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"))
    candidates.append(Path("/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home"))

    for candidate in candidates:
        java_bin = candidate / "bin/java"
        if java_bin.exists():
            return candidate.resolve()

    raise FileNotFoundError("No supported JAVA_HOME found for Ghidra")


def resolve_analyze_headless(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        root = Path(explicit).expanduser()
        candidates.extend(
            [
                root / "support/analyzeHeadless",
                root / "libexec/support/analyzeHeadless",
                root / "Contents/Resources/Java/support/analyzeHeadless",
            ]
        )

    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home:
        root = Path(ghidra_home).expanduser()
        candidates.extend([root / "support/analyzeHeadless", root / "libexec/support/analyzeHeadless"])

    which_path = shutil.which("analyzeHeadless")
    if which_path:
        candidates.append(Path(which_path))

    candidates.extend(
        [
            Path("/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless"),
            Path("/usr/local/opt/ghidra/libexec/support/analyzeHeadless"),
        ]
    )

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    raise FileNotFoundError("analyzeHeadless not found; install Ghidra or pass --ghidra-home")


def detect_psx_loader_installation() -> Path | None:
    home = Path.home()
    glob_patterns = [
        home / "Library/ghidra",
        home / ".config/ghidra",
    ]
    for root in glob_patterns:
        if not root.exists():
            continue
        matches = sorted(root.glob("ghidra_*_PUBLIC/Extensions/ghidra_psx_ldr/extension.properties"))
        if matches:
            return matches[-1].parent

    explicit_candidates = [
        Path("/opt/homebrew/opt/ghidra/libexec/Ghidra/Extensions/ghidra_psx_ldr"),
        Path("/usr/local/opt/ghidra/libexec/Ghidra/Extensions/ghidra_psx_ldr"),
    ]
    for candidate in explicit_candidates:
        if (candidate / "extension.properties").exists():
            return candidate.resolve()

    return None


def run_command(command: list[str], env: dict[str, str], log_path: Path) -> None:
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    combined_output = result.stdout + result.stderr
    write_output(log_path, combined_output.encode("utf-8", errors="replace"))
    if result.returncode != 0:
        raise RuntimeError(f"Ghidra import failed. See log: {log_path}")


def main() -> int:
    args = parse_args()
    image_path = Path(args.image).expanduser().resolve()
    extract_dir = Path(args.extract_dir).expanduser().resolve() if args.extract_dir else image_path.parent / "extracted"
    analysis, extracted_blobs = collect_disc_analysis(str(image_path))

    extract_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = extract_dir / "manifest.json"
    write_output(manifest_path, json.dumps(analysis, indent=2, sort_keys=True).encode("utf-8"))

    for raw_name, blob in extracted_blobs.items():
        entry = next(item for item in analysis["visible_entries"] if item["raw_name"] == raw_name)
        output_path = extract_dir / str(entry["path"])
        if not output_path.exists():
            write_output(output_path, blob)

    project_root = Path(args.project_root).expanduser().resolve() if args.project_root else image_path.parent / "analysis/ghidra"
    project_name = sanitize_project_name(args.project_name or f"{image_path.stem}_PS1")
    project_root.mkdir(parents=True, exist_ok=True)

    if args.reset_project:
        for suffix in [".gpr", ".rep"]:
            candidate = project_root / f"{project_name}{suffix}"
            if candidate.is_dir():
                shutil.rmtree(candidate)
            elif candidate.exists():
                candidate.unlink()

    java_home = resolve_java_home(args.java_home)
    analyze_headless = resolve_analyze_headless(args.ghidra_home)
    script_dir = Path(__file__).resolve().parents[1] / "ghidra_scripts"
    logs_dir = project_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["JAVA_HOME"] = str(java_home)
    env["PATH"] = f"{java_home / 'bin'}:{env.get('PATH', '')}"

    psx_loader_installation = None if args.force_raw_loader else detect_psx_loader_installation()
    use_psx_loader = psx_loader_installation is not None

    executables = analysis["psx_executables"]
    if args.boot_only:
        executables = [item for item in executables if item["raw_name"] == analysis["boot_raw_name"]]

    if not executables:
        raise ValueError("No PS-X executables were discovered to import")

    imported_programs: list[dict[str, object]] = []
    for executable in executables:
        header = executable["header"]
        program_path = extract_dir / str(executable["path"])
        import_log = logs_dir / f"{Path(str(executable['path'])).name}.headless.log"
        command = [
            str(analyze_headless),
            str(project_root),
            project_name,
            "-import",
            str(program_path),
        ]

        if use_psx_loader:
            command.extend([
                "-loader",
                PSX_LOADER_CLASS,
            ])
        else:
            command.extend([
                "-loader",
                "BinaryLoader",
                "-loader-baseAddr",
                hex(header["load_address"]),
                "-loader-fileOffset",
                hex(PSX_EXE_HEADER_SIZE),
                "-loader-length",
                hex(header["payload_size"]),
                "-processor",
                args.processor,
                "-scriptPath",
                str(script_dir),
                "-preScript",
                "SeedPsxEntry.java",
                hex(header["initial_pc"]),
                str(Path(str(executable["path"])).stem),
            ])

        command.extend([
            "-overwrite",
            "-log",
            str(import_log),
            "-scriptlog",
            str(logs_dir / f"{Path(str(executable['path'])).name}.script.log"),
        ])
        if args.noanalysis:
            command.append("-noanalysis")

        run_command(command, env, import_log)
        imported_programs.append(
            {
                "program": str(executable["path"]),
                "raw_name": executable["raw_name"],
                "log": str(import_log),
                "entry_point": header["initial_pc"],
                "load_address": header["load_address"],
                "loader_mode": "ghidra_psx_ldr" if use_psx_loader else "raw_binary_fallback",
                "language": PSX_PROCESSOR if use_psx_loader else args.processor,
            }
        )

    report = {
        "image": str(image_path),
        "manifest": str(manifest_path),
        "extract_dir": str(extract_dir),
        "project_root": str(project_root),
        "project_name": project_name,
        "project_file": str(project_root / f"{project_name}.gpr"),
        "java_home": str(java_home),
        "analyze_headless": str(analyze_headless),
        "processor": args.processor,
        "psx_loader_installed": psx_loader_installation is not None,
        "psx_loader_installation": str(psx_loader_installation) if psx_loader_installation else None,
        "default_loader_mode": "ghidra_psx_ldr" if use_psx_loader else "raw_binary_fallback",
        "analysis_enabled": not args.noanalysis,
        "imported_programs": imported_programs,
    }
    report_path = project_root / "ps1_pipeline_report.json"
    write_output(report_path, json.dumps(report, indent=2, sort_keys=True).encode("utf-8"))

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)