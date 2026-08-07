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

: "${WASP_SSH_SOCKET:?Set WASP_SSH_SOCKET in the local WASP environment file}"
: "${WASP_REMOTE_HOST:?Set WASP_REMOTE_HOST in the local WASP environment file}"
: "${WASP_REMOTE_ROOT:?Set WASP_REMOTE_ROOT in the local WASP environment file}"

remote_env=(
	"WASP_CONTAINER_RUNTIME=${WASP_CONTAINER_RUNTIME:-auto}"
	"WASP_REMOTE_ROOT=$WASP_REMOTE_ROOT"
	"WASP_GITLAB_TAR=${WASP_GITLAB_TAR:-}"
	"WASP_REDDIT_TAR=${WASP_REDDIT_TAR:-}"
	"WASP_GITLAB_SANDBOX=${WASP_GITLAB_SANDBOX:-}"
	"WASP_REDDIT_SANDBOX=${WASP_REDDIT_SANDBOX:-}"
	"WASP_REQUIRE_ARCHIVE_VERIFICATION=${WASP_REQUIRE_ARCHIVE_VERIFICATION:-0}"
	"WASP_GITLAB_IMAGE_SHA256=${WASP_GITLAB_IMAGE_SHA256:-}"
	"WASP_REDDIT_IMAGE_SHA256=${WASP_REDDIT_IMAGE_SHA256:-}"
	"WASP_GITLAB_IMAGE_BYTES=${WASP_GITLAB_IMAGE_BYTES:-}"
	"WASP_REDDIT_IMAGE_BYTES=${WASP_REDDIT_IMAGE_BYTES:-}"
	"WASP_GITLAB_REMOTE_PORT=${WASP_GITLAB_REMOTE_PORT:-8023}"
	"WASP_REDDIT_REMOTE_PORT=${WASP_REDDIT_REMOTE_PORT:-9999}"
	"WASP_PUBLIC_GITLAB_URL=${GITLAB:-http://127.0.0.1:18023}"
)

ssh -S "$WASP_SSH_SOCKET" -O check "$WASP_REMOTE_HOST"
ssh -S "$WASP_SSH_SOCKET" "$WASP_REMOTE_HOST" \
	env "${remote_env[@]}" bash -s -- reset < "$SCRIPT_DIR/remote-environment.sh"

bash "$SCRIPT_DIR/forward-ports.sh"

curl --fail --silent --show-error --output /dev/null \
	"${GITLAB:-http://127.0.0.1:18023}/explore"
curl --fail --silent --show-error --output /dev/null \
	"${REDDIT:-http://127.0.0.1:19999}/"
curl --fail --silent --show-error --output /dev/null \
	"${WASP_OLLAMA_HOST:-http://127.0.0.1:11435}/api/tags"

echo "Pristine WASP environment reset and all local forwards are healthy."
