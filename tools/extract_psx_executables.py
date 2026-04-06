#!/usr/bin/env python3
"""Extract visible PS1 executables from common disc-image layouts."""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

FORM1_DATA_SIZE = 2048
PRIMARY_VOLUME_DESCRIPTOR_SECTOR = 16
PSX_EXE_MAGIC = b"PS-X EXE"
PSX_EXE_HEADER_SIZE = 0x800


@dataclass(frozen=True)
class ImageLayout:
    name: str
    sector_size: int
    data_offset: int
    data_size: int = FORM1_DATA_SIZE


LAYOUT_CANDIDATES = [
    ImageLayout("iso9660/2048", 2048, 0),
    ImageLayout("mode1/2352", 2352, 16),
    ImageLayout("mode2/2352", 2352, 24),
]


@dataclass(frozen=True)
class DirEntry:
    raw_name: str
    path: str
    extent: int
    size: int
    flags: int

    @property
    def is_dir(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def normalized_name(self) -> str:
        return strip_version(self.raw_name)


class DiscImage:
    def __init__(self, path: Path, layout: ImageLayout) -> None:
        self.path = path
        self.layout = layout
        self.handle = path.open("rb")

    def close(self) -> None:
        self.handle.close()

    def __enter__(self) -> "DiscImage":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def read_sector(self, sector_index: int) -> bytes:
        self.handle.seek(sector_index * self.layout.sector_size + self.layout.data_offset)
        raw = self.handle.read(self.layout.data_size)
        if len(raw) != self.layout.data_size:
            raise ValueError(f"short read at sector {sector_index}")
        return raw

    def read_extent(self, extent: int, size: int) -> bytes:
        sectors = (size + self.layout.data_size - 1) // self.layout.data_size
        chunks = bytearray()
        for offset in range(sectors):
            chunks.extend(self.read_sector(extent + offset))
        return bytes(chunks[:size])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "List visible ISO9660 files in a PS1 MODE2/2352 image and extract "
            "boot executables for Ghidra analysis."
        )
    )
    parser.add_argument("image", help="Path to a .cue or raw .bin image")
    parser.add_argument(
        "--out-dir",
        help="Output directory for extracted files (defaults to <image-dir>/extracted)",
    )
    parser.add_argument(
        "--extract-defaults",
        action="store_true",
        help="Extract SYSTEM.CNF and every visible PS-X EXE discovered on the disc",
    )
    parser.add_argument(
        "--extract",
        action="append",
        default=[],
        metavar="NAME",
        help="Extract an additional visible file by raw or normalized name",
    )
    parser.add_argument(
        "--manifest-name",
        default="manifest.json",
        help="Filename to use for the JSON analysis manifest inside the output directory",
    )
    return parser.parse_args()


def resolve_image_path(image_arg: str) -> tuple[Path, Path]:
    image_path = Path(image_arg).expanduser().resolve()
    if not image_path.exists():
        raise FileNotFoundError(f"image not found: {image_path}")
    if image_path.suffix.lower() != ".cue":
        return image_path, image_path

    cue_text = image_path.read_text(encoding="utf-8", errors="replace")
    current_file: str | None = None
    for raw_line in cue_text.splitlines():
        line = raw_line.strip()
        file_match = re.match(r'^FILE\s+"([^"]+)"\s+BINARY\s*$', line, flags=re.IGNORECASE)
        if file_match:
            current_file = file_match.group(1)
            continue
        track_match = re.match(r'^TRACK\s+\d+\s+(MODE1/2048|MODE1/2352|MODE2/2352)\s*$', line, flags=re.IGNORECASE)
        if track_match and current_file is not None:
            bin_path = (image_path.parent / current_file).resolve()
            if not bin_path.exists():
                raise FileNotFoundError(f"BIN referenced by cue sheet not found: {bin_path}")
            return image_path, bin_path

    match = re.search(r'^FILE\s+"([^"]+)"\s+BINARY\s*$', cue_text, flags=re.IGNORECASE | re.MULTILINE)
    if not match:
        raise ValueError(f"could not resolve BIN from cue sheet: {image_path}")

    bin_path = (image_path.parent / match.group(1)).resolve()
    if not bin_path.exists():
        raise FileNotFoundError(f"BIN referenced by cue sheet not found: {bin_path}")
    return image_path, bin_path


def detect_image_layout(path: Path) -> ImageLayout:
    with path.open("rb") as handle:
        for layout in LAYOUT_CANDIDATES:
            handle.seek(PRIMARY_VOLUME_DESCRIPTOR_SECTOR * layout.sector_size + layout.data_offset)
            if handle.read(6) == b"\x01CD001":
                return layout
    raise ValueError(f"unsupported image layout for {path}")


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def strip_version(name: str) -> str:
    return name.split(";", 1)[0]


def read_root_directory(image: DiscImage) -> tuple[int, int]:
    pvd = image.read_sector(PRIMARY_VOLUME_DESCRIPTOR_SECTOR)
    if pvd[:6] != b"\x01CD001":
        raise ValueError("primary volume descriptor not found at sector 16")

    record_length = pvd[156]
    record = pvd[156:156 + record_length]
    return u32(record, 2), u32(record, 10)


def parse_directory_entries(image: DiscImage, extent: int, size: int, prefix: str = "") -> list[DirEntry]:
    entries: list[DirEntry] = []
    data = image.read_extent(extent, size)
    offset = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset = ((offset // image.layout.data_size) + 1) * image.layout.data_size
            continue

        record = data[offset:offset + length]
        name_length = record[32]
        raw_name = record[33:33 + name_length].decode("ascii", errors="replace")
        entry = DirEntry(
            raw_name=raw_name,
            path=f"{prefix}{strip_version(raw_name)}",
            extent=u32(record, 2),
            size=u32(record, 10),
            flags=record[25],
        )
        entries.append(entry)
        if entry.is_dir and raw_name not in {"\x00", "\x01"}:
            child_prefix = f"{entry.path}/"
            entries.extend(parse_directory_entries(image, entry.extent, entry.size, prefix=child_prefix))
        offset += length
    return entries


def find_entry(entries: list[DirEntry], name: str) -> DirEntry | None:
    needle = name.upper()
    needle_no_ver = strip_version(name).upper()
    for entry in entries:
        if entry.raw_name.upper() == needle:
            return entry
        if entry.normalized_name.upper() == needle_no_ver:
            return entry
        if entry.path.upper() == needle_no_ver:
            return entry
    return None


def parse_system_cnf(text: str) -> str:
    match = re.search(r"BOOT\s*=\s*cdrom:\\\\?([^\r\n]+)", text, flags=re.IGNORECASE)
    if not match:
        raise ValueError("BOOT entry not found in SYSTEM.CNF")
    return match.group(1).strip().replace("\\", "/").lstrip("/")


def parse_psx_exe_header(data: bytes) -> dict[str, int]:
    if not data.startswith(PSX_EXE_MAGIC):
        raise ValueError("file does not start with a PS-X EXE header")
    return {
        "initial_pc": u32(data, 0x10),
        "initial_gp": u32(data, 0x14),
        "load_address": u32(data, 0x18),
        "payload_size": u32(data, 0x1C),
        "initial_sp": u32(data, 0x30),
    }


def write_output(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def print_entry_table(entries: list[DirEntry]) -> None:
    print("Visible ISO9660 entries:")
    for entry in entries:
        if entry.raw_name in {"\x00", "\x01"}:
            continue
        kind = "DIR " if entry.is_dir else "FILE"
        print(f"  {kind}  {entry.path:<18} LBA={entry.extent:<6} size={entry.size}")


def print_exe_summary(name: str, header: dict[str, int]) -> None:
    print(f"PS-X EXE summary for {name}:")
    print(f"  Entry point : 0x{header['initial_pc']:08X}")
    print(f"  Load address: 0x{header['load_address']:08X}")
    print(f"  Payload size: 0x{header['payload_size']:X} ({header['payload_size']})")
    print(f"  Initial GP  : 0x{header['initial_gp']:08X}")
    print(f"  Initial SP  : 0x{header['initial_sp']:08X}")


def entry_to_manifest(entry: DirEntry) -> dict[str, object]:
    return {
        "raw_name": entry.raw_name,
        "path": entry.path,
        "extent": entry.extent,
        "size": entry.size,
        "flags": entry.flags,
        "is_dir": entry.is_dir,
    }


def discover_psx_executables(image: DiscImage, entries: list[DirEntry]) -> list[dict[str, object]]:
    executables: list[dict[str, object]] = []
    for entry in entries:
        if entry.is_dir or entry.raw_name in {"\x00", "\x01"} or entry.size < len(PSX_EXE_MAGIC):
            continue
        header_probe = image.read_extent(entry.extent, min(entry.size, PSX_EXE_HEADER_SIZE))
        if not header_probe.startswith(PSX_EXE_MAGIC):
            continue
        executables.append(
            {
                **entry_to_manifest(entry),
                "header": parse_psx_exe_header(header_probe),
            }
        )
    return executables


def collect_disc_analysis(image_arg: str) -> tuple[dict[str, object], dict[str, bytes]]:
    cue_path, bin_path = resolve_image_path(image_arg)
    layout = detect_image_layout(bin_path)

    with DiscImage(bin_path, layout) as image:
        root_extent, root_size = read_root_directory(image)
        entries = parse_directory_entries(image, root_extent, root_size)
        system_entry = find_entry(entries, "SYSTEM.CNF")
        if system_entry is None:
            raise ValueError("SYSTEM.CNF not found in visible filesystem")

        system_cnf = image.read_extent(system_entry.extent, system_entry.size)
        system_text = system_cnf.decode("ascii", errors="replace").strip()
        boot_name = parse_system_cnf(system_text)
        boot_entry = find_entry(entries, boot_name)
        if boot_entry is None:
            raise ValueError(f"boot executable not found: {boot_name}")

        boot_data = image.read_extent(boot_entry.extent, boot_entry.size)
        psx_executables = discover_psx_executables(image, entries)
        psx_by_raw_name = {item["raw_name"]: item for item in psx_executables}

        visible_entries = [entry_to_manifest(entry) for entry in entries if entry.raw_name not in {"\x00", "\x01"}]
        files_to_extract = {
            system_entry.raw_name: system_cnf,
            boot_entry.raw_name: boot_data,
        }
        for executable in psx_executables:
            raw_name = executable["raw_name"]
            if raw_name not in files_to_extract:
                entry = find_entry(entries, raw_name)
                if entry is not None:
                    files_to_extract[raw_name] = image.read_extent(entry.extent, entry.size)

        analysis = {
            "image": str(cue_path),
            "raw_image": str(bin_path),
            "layout": {
                "name": layout.name,
                "sector_size": layout.sector_size,
                "data_offset": layout.data_offset,
                "data_size": layout.data_size,
            },
            "system_cnf": system_text,
            "boot": {
                **entry_to_manifest(boot_entry),
                "header": parse_psx_exe_header(boot_data),
            },
            "visible_entries": visible_entries,
            "psx_executables": psx_executables,
            "boot_raw_name": boot_entry.raw_name,
            "boot_path": boot_entry.path,
            "has_sys_exe": "SYS.EXE;1" in psx_by_raw_name,
        }

        return analysis, files_to_extract


def find_visible_entry_info(analysis: dict[str, object], requested_name: str) -> dict[str, object] | None:
    needle = requested_name.upper()
    needle_no_ver = strip_version(requested_name).upper()
    for entry in analysis["visible_entries"]:
        raw_name = str(entry["raw_name"])
        path = str(entry["path"])
        if raw_name.upper() == needle:
            return entry
        if strip_version(raw_name).upper() == needle_no_ver:
            return entry
        if path.upper() == needle_no_ver:
            return entry
    return None


def read_visible_entry_blob(image_arg: str, analysis: dict[str, object], entry: dict[str, object]) -> bytes:
    _, bin_path = resolve_image_path(image_arg)
    layout_info = analysis["layout"]
    layout = ImageLayout(
        name=str(layout_info["name"]),
        sector_size=int(layout_info["sector_size"]),
        data_offset=int(layout_info["data_offset"]),
        data_size=int(layout_info["data_size"]),
    )
    with DiscImage(bin_path, layout) as image:
        return image.read_extent(int(entry["extent"]), int(entry["size"]))


def main() -> int:
    args = parse_args()
    cue_path, _ = resolve_image_path(args.image)
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else cue_path.parent / "extracted"
    analysis, extracted_blobs = collect_disc_analysis(args.image)

    print(f"Image: {analysis['image']}")
    print(f"Raw BIN: {analysis['raw_image']}")
    print(f"Detected layout: {analysis['layout']['name']}")
    print("Visible ISO9660 entries:")
    for entry in analysis["visible_entries"]:
        kind = "DIR " if entry["is_dir"] else "FILE"
        print(f"  {kind}  {entry['path']:<18} LBA={entry['extent']:<6} size={entry['size']}")

    print("SYSTEM.CNF:")
    for line in str(analysis["system_cnf"]).splitlines():
        print(f"  {line}")
    print(f"Boot executable: {analysis['boot']['raw_name']}")
    for executable in analysis["psx_executables"]:
        print_exe_summary(str(executable["raw_name"]), executable["header"])

    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / args.manifest_name
    write_output(manifest_path, json.dumps(analysis, indent=2, sort_keys=True).encode("utf-8"))
    print(f"Manifest: {manifest_path}")

    to_extract_names: list[str] = []
    if args.extract_defaults:
        to_extract_names.append("SYSTEM.CNF;1")
        to_extract_names.extend(executable["raw_name"] for executable in analysis["psx_executables"])

    to_extract_names.extend(args.extract)

    seen_names: set[str] = set()
    if to_extract_names:
        print(f"Writing extracted files to {out_dir}")
        for requested_name in to_extract_names:
            entry_name = requested_name if requested_name in extracted_blobs else None
            entry_info: dict[str, object] | None = None
            if entry_name is None:
                match = next(
                    (name for name in extracted_blobs if strip_version(name).upper() == strip_version(requested_name).upper()),
                    None,
                )
                if match is not None:
                    entry_name = match
                else:
                    entry_info = find_visible_entry_info(analysis, requested_name)
                    if entry_info is None:
                        raise ValueError(f"file not found in visible filesystem: {requested_name}")
                    entry_name = str(entry_info["raw_name"])
            if entry_name in seen_names:
                continue
            seen_names.add(entry_name)

            if entry_info is None:
                entry_info = next(
                    item for item in analysis["visible_entries"] if item["raw_name"] == entry_name
                )
            data = extracted_blobs.get(entry_name)
            if data is None:
                if bool(entry_info["is_dir"]):
                    raise ValueError(f"cannot extract directory entry: {requested_name}")
                data = read_visible_entry_blob(args.image, analysis, entry_info)
                extracted_blobs[entry_name] = data
            output_path = out_dir / str(entry_info["path"])
            write_output(output_path, data)
            print(f"  wrote {output_path}")
            if data.startswith(PSX_EXE_MAGIC):
                header = parse_psx_exe_header(data)
                info_path = output_path.with_suffix(output_path.suffix + ".txt")
                info_text = (
                    f"File: {entry_name}\n"
                    f"Entry point: 0x{header['initial_pc']:08X}\n"
                    f"Load address: 0x{header['load_address']:08X}\n"
                    f"Payload size: 0x{header['payload_size']:X} ({header['payload_size']})\n"
                    f"Initial GP: 0x{header['initial_gp']:08X}\n"
                    f"Initial SP: 0x{header['initial_sp']:08X}\n"
                )
                write_output(info_path, info_text.encode("utf-8"))
                print(f"  wrote {info_path}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)