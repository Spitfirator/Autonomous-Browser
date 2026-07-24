#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_ENV="${WASP_LOCAL_ENV:-$SCRIPT_DIR/wasp.local.env}"

if [ ! -f "$LOCAL_ENV" ]; then
	echo "Missing $LOCAL_ENV; copy wasp.local.env.example and fill in the remote host." >&2
	exit 2
fi

set -a
# shellcheck disable=SC1090
. "$LOCAL_ENV"
set +a

: "${WASP_SSH_SOCKET:?Set WASP_SSH_SOCKET in the local environment file}"
: "${WASP_REMOTE_HOST:?Set WASP_REMOTE_HOST in the local environment file}"

ssh -S "$WASP_SSH_SOCKET" -O check "$WASP_REMOTE_HOST"

forward() {
	local local_port="$1"
	local remote_port="$2"
	if ssh -S "$WASP_SSH_SOCKET" -O forward \
		-L "${local_port}:127.0.0.1:${remote_port}" "$WASP_REMOTE_HOST" 2>/dev/null; then
		echo "Forwarded localhost:${local_port} -> ${WASP_REMOTE_HOST}:${remote_port}"
	else
		echo "Forward localhost:${local_port} may already exist; checking it instead."
	fi
}

forward "${WASP_GITLAB_LOCAL_PORT:-18023}" "${WASP_GITLAB_REMOTE_PORT:-8023}"
forward "${WASP_REDDIT_LOCAL_PORT:-19999}" "${WASP_REDDIT_REMOTE_PORT:-9999}"
forward "${WASP_OLLAMA_LOCAL_PORT:-11435}" "${WASP_OLLAMA_REMOTE_PORT:-11434}"

curl --fail --silent --show-error --max-time 10 \
	"${WASP_OLLAMA_HOST:-http://127.0.0.1:11435}/api/tags" >/dev/null
echo "Ollama forward is reachable."
