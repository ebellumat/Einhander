#!/usr/bin/env bash
set -euo pipefail

ZIP_PATH="${1:-}"
if [[ -z "$ZIP_PATH" ]]; then
  echo "Usage: $0 /path/to/ghidra_psx_ldr.zip" >&2
  exit 1
fi

if [[ ! -f "$ZIP_PATH" ]]; then
  echo "Error: zip file not found at $ZIP_PATH" >&2
  exit 1
fi

if [[ -n "${GHIDRA_SETTINGS_DIR:-}" ]]; then
  SETTINGS_DIR="$GHIDRA_SETTINGS_DIR"
else
  SETTINGS_DIR="$(find "$HOME/Library/ghidra" -maxdepth 1 -type d -name 'ghidra_*_PUBLIC' | sort | tail -n 1)"
fi

if [[ -z "$SETTINGS_DIR" || ! -d "$SETTINGS_DIR" ]]; then
  echo "Error: could not locate the Ghidra settings directory." >&2
  echo "Set GHIDRA_SETTINGS_DIR manually if needed." >&2
  exit 1
fi

EXT_DIR="$SETTINGS_DIR/Extensions"
mkdir -p "$EXT_DIR"
rm -rf "$EXT_DIR/ghidra_psx_ldr"

cd "$EXT_DIR"
unzip -q "$ZIP_PATH"

if [[ ! -f "$EXT_DIR/ghidra_psx_ldr/extension.properties" ]]; then
  echo "Error: extension was extracted, but extension.properties was not found." >&2
  exit 1
fi

rm -rf "$SETTINGS_DIR/osgi/felixcache"/* "$SETTINGS_DIR/osgi/compiled-bundles"/* 2>/dev/null || true

echo "Extension installed at: $EXT_DIR/ghidra_psx_ldr"
echo "OSGi cache cleared at: $SETTINGS_DIR/osgi"
echo "Restart Ghidra to ensure the extension is reloaded in the UI."