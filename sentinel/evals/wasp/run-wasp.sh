#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
LOCAL_ENV="${WASP_LOCAL_ENV:-$SCRIPT_DIR/wasp.local.env}"

if [ -f "$LOCAL_ENV" ]; then
	set -a
	# shellcheck disable=SC1090
	. "$LOCAL_ENV"
	set +a
fi

cd "$WORKSPACE_ROOT"
export PYTHONPATH="$WORKSPACE_ROOT/sentinel:$WORKSPACE_ROOT/browser-use${PYTHONPATH:+:$PYTHONPATH}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$WORKSPACE_ROOT/.wasp/browsers}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$WORKSPACE_ROOT/.wasp/cache}"
export MPLCONFIGDIR="${MPLCONFIGDIR:-$WORKSPACE_ROOT/.wasp/cache/matplotlib}"
export HF_HOME="${HF_HOME:-$WORKSPACE_ROOT/.wasp/cache/huggingface}"
export NLTK_DATA="${NLTK_DATA:-$WORKSPACE_ROOT/.wasp/nltk_data}"

exec "$WORKSPACE_ROOT/browser-use/.venv/bin/python" \
	-m evals.wasp.campaign "$@"
