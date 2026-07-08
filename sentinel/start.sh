#!/usr/bin/env bash
# Sentinel launcher: builds the extension bundle if missing, then starts the
# backend (which launches the dedicated Chrome window) using browser-use's venv.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$ROOT/extension/dist/manifest.json" ]; then
	echo "[sentinel] extension/dist missing — building it (first run only)..."
	(cd "$ROOT/extension" && npm install && npm run build)
fi

cd "$ROOT"   # puts sentinel/ on sys.path so `python -m server.main` resolves
exec uv run --project "$ROOT/../browser-use" --no-sync python -m server.main
