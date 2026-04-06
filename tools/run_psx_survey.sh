#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUN_GHIDRA="$ROOT_DIR/tools/run_ghidra.sh"
SCRIPT_DIR="$ROOT_DIR/ghidra_scripts"

PROJECT_ROOT="${1:-$PWD/analysis/ghidra}"
PROJECT_NAME="${2:-PS1_Project}"
PROGRAM_NAME="${3:-SCUS_000.00}"
OUT_DIR="${4:-$PROJECT_ROOT/reports}"

if [[ ! -x "$RUN_GHIDRA" ]]; then
  echo "Error: Ghidra launcher not found at $RUN_GHIDRA" >&2
  exit 1
fi

ANALYZE_HEADLESS="/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless"
if [[ ! -x "$ANALYZE_HEADLESS" ]]; then
  echo "Error: analyzeHeadless not found at $ANALYZE_HEADLESS" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}" \
PATH="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}/bin:$PATH" \
"$ANALYZE_HEADLESS" \
  "$PROJECT_ROOT" "$PROJECT_NAME" \
  -process "$PROGRAM_NAME" \
  -readOnly \
  -noanalysis \
  -scriptPath "$SCRIPT_DIR" \
  -postScript ExportPsxSurvey.java "$OUT_DIR" \
  -log "$OUT_DIR/${PROGRAM_NAME}.survey.headless.log" \
  -scriptlog "$OUT_DIR/${PROGRAM_NAME}.survey.script.log"