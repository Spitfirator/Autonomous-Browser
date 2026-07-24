#!/usr/bin/env bash
# Strictly serialize the controlled 4B AgentDojo rerun and the WASP campaign.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
LOCAL_ENV="${WASP_LOCAL_ENV:-$SCRIPT_DIR/wasp.local.env}"
AGENTDOJO_STATE="${AGENTDOJO_STATE:-$WORKSPACE_ROOT/sentinel/evals/agentdojo-campaign-v1-qwen35-4b-thinking-state.json}"
POLL_SECONDS="${WASP_QUEUE_POLL_SECONDS:-60}"
QUEUE_LOG="${WASP_QUEUE_LOG:-$WORKSPACE_ROOT/sentinel/evals/wasp-queue-after-4b.log}"

if [ ! -f "$LOCAL_ENV" ]; then
	echo "Missing $LOCAL_ENV; copy wasp.local.env.example and fill in the remote host." >&2
	exit 2
fi

set -a
# shellcheck disable=SC1090
. "$LOCAL_ENV"
set +a

mkdir -p "$(dirname "$QUEUE_LOG")"

: "${WASP_SSH_SOCKET:?Set WASP_SSH_SOCKET in the local environment file}"
: "${WASP_REMOTE_HOST:?Set WASP_REMOTE_HOST in the local environment file}"

say() {
	line="[$(date -u +%FT%TZ)] $*"
	printf '%s\n' "$line"
	printf '%s\n' "$line" >> "$QUEUE_LOG"
}

agentdojo_complete() {
	jq -e '
		.kind == "agentdojo-campaign-state" and
		.model == "qwen3.5-agentdojo:4b" and
		.completed_pairs == 629 and .total_pairs == 629 and
		.completed_executions == 1258 and .total_executions == 1258
	' "$AGENTDOJO_STATE" >/dev/null 2>&1
}

say "WASP is queued behind the controlled 4B AgentDojo rerun."
until agentdojo_complete; do
	completed=$(jq -r '.completed_executions // 0' "$AGENTDOJO_STATE" 2>/dev/null || echo 0)
	say "Waiting for 4B: ${completed}/1258 executions checkpointed."
	sleep "$POLL_SECONDS"
done

say "4B checkpoint is complete; verifying the SSH master."
ssh -S "$WASP_SSH_SOCKET" -O check "$WASP_REMOTE_HOST"

while ssh -S "$WASP_SSH_SOCKET" "$WASP_REMOTE_HOST" \
	pgrep -f '[r]emote-environment.sh download' >/dev/null; do
	say "Official WASP image download is still running; waiting before preparation."
	sleep "$POLL_SECONDS"
done

remote_env=(
	"WASP_CONTAINER_RUNTIME=${WASP_CONTAINER_RUNTIME:-auto}"
	"WASP_REMOTE_ROOT=${WASP_REMOTE_ROOT:-${WASP_REMOTE_SCRATCH:-/scratch0/$USER/wasp}}"
	"WASP_GITLAB_TAR=${WASP_GITLAB_TAR:-}"
	"WASP_REDDIT_TAR=${WASP_REDDIT_TAR:-}"
	"WASP_GITLAB_SANDBOX=${WASP_GITLAB_SANDBOX:-}"
	"WASP_REDDIT_SANDBOX=${WASP_REDDIT_SANDBOX:-}"
	"WASP_GITLAB_REMOTE_PORT=${WASP_GITLAB_REMOTE_PORT:-8023}"
	"WASP_REDDIT_REMOTE_PORT=${WASP_REDDIT_REMOTE_PORT:-9999}"
	"WASP_PUBLIC_GITLAB_URL=${GITLAB:-http://127.0.0.1:18023}"
)

say "Starting pristine WASP website environments."
ssh -S "$WASP_SSH_SOCKET" "$WASP_REMOTE_HOST" \
	env "${remote_env[@]}" bash -s -- start < "$SCRIPT_DIR/remote-environment.sh"

say "Opening website and Ollama forwards."
bash "$SCRIPT_DIR/forward-ports.sh"

say "Running the full WASP preflight."
bash "$SCRIPT_DIR/run-wasp.sh" preflight

say "Preflight passed; launching the paired WASP campaign."
exec bash "$SCRIPT_DIR/run-wasp.sh" run
