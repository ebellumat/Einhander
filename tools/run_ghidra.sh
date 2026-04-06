#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
  RESOLVED_JAVA_HOME="$JAVA_HOME"
elif [[ -x "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home/bin/java" ]]; then
  RESOLVED_JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
elif [[ -x "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home/bin/java" ]]; then
  RESOLVED_JAVA_HOME="/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home"
else
  echo "Error: no compatible JAVA_HOME was found for Ghidra." >&2
  exit 1
fi

if [[ -x "/opt/homebrew/bin/ghidraRun" ]]; then
  GHIDRA_RUN="/opt/homebrew/bin/ghidraRun"
elif [[ -n "${GHIDRA_HOME:-}" && -x "${GHIDRA_HOME}/ghidraRun" ]]; then
  GHIDRA_RUN="${GHIDRA_HOME}/ghidraRun"
elif [[ -n "${GHIDRA_HOME:-}" && -x "${GHIDRA_HOME}/support/ghidraRun" ]]; then
  GHIDRA_RUN="${GHIDRA_HOME}/support/ghidraRun"
else
  echo "Error: ghidraRun was not found." >&2
  exit 1
fi

export JAVA_HOME="$RESOLVED_JAVA_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

exec "$GHIDRA_RUN" "$@"