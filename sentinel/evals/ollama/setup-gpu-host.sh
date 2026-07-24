#!/usr/bin/env bash
# Bootstrap a user-space Ollama server for AgentDojo campaigns on a GPU host
# (no sudo required). Run this ON the GPU host, e.g.:
#
#   ssh -S /tmp/agentdojo-gpu.sock user@gpu-host.example \
#     'bash -s' < sentinel/evals/ollama/setup-gpu-host.sh
#
# Then forward the port from the laptop and point the harness at it:
#
#   ssh -S /tmp/agentdojo-gpu.sock -O forward -L 11434:127.0.0.1:11434 \
#     user@gpu-host.example
#
# Optional overrides:
#   MODEL_TAG=qwen3.5:14b   force a specific base tag (skips VRAM auto-pick)
#   OLLAMA_DIR=/scratch/... install Ollama outside an ephemeral home quota
#   OLLAMA_MODELS=/path     store model weights outside $HOME (quota relief)
#   OLLAMA_VERSION=v0.30.8  pinned Ollama release
#   OLLAMA_SHA256=...       required when overriding OLLAMA_VERSION
#   NUM_CTX=32768           context length pinned into the campaign model
set -euo pipefail

OLLAMA_DIR="${OLLAMA_DIR:-$HOME/.local/ollama}"
OLLAMA_VERSION="${OLLAMA_VERSION:-v0.30.8}"
if [ -z "${OLLAMA_SHA256:-}" ]; then
	if [ "$OLLAMA_VERSION" = "v0.30.8" ]; then
		OLLAMA_SHA256="ffe2b2c2f2f5f5b30c081ec353c2e0bb2d9ead516064a8e22663b24b8fd8dca0"
	else
		echo "Set OLLAMA_SHA256 when overriding OLLAMA_VERSION=$OLLAMA_VERSION" >&2
		exit 1
	fi
fi
OLLAMA_ASSET_URL="https://github.com/ollama/ollama/releases/download/$OLLAMA_VERSION/ollama-linux-amd64.tar.zst"
OLLAMA_HOST_ADDR="127.0.0.1:11434"
NUM_CTX="${NUM_CTX:-32768}"
LOG_FILE="${OLLAMA_LOG_FILE:-$OLLAMA_DIR/ollama-server.log}"

say() { printf '\n== %s\n' "$*"; }

# --- 1. Install a user-space Ollama if none is available -------------------
if command -v ollama >/dev/null 2>&1; then
	OLLAMA_BIN="$(command -v ollama)"
elif [ -x "$OLLAMA_DIR/bin/ollama" ]; then
	OLLAMA_BIN="$OLLAMA_DIR/bin/ollama"
else
	say "Installing Ollama into $OLLAMA_DIR (user-space, no sudo)"
	mkdir -p "$OLLAMA_DIR"
	OLLAMA_ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/ollama-linux-amd64.XXXXXX.tar.zst")"
	trap 'rm -f "$OLLAMA_ARCHIVE"' EXIT
	curl -fL --progress-bar "$OLLAMA_ASSET_URL" -o "$OLLAMA_ARCHIVE"
	printf '%s  %s\n' "$OLLAMA_SHA256" "$OLLAMA_ARCHIVE" | sha256sum -c -
	if command -v zstd >/dev/null 2>&1; then
		zstd -dc "$OLLAMA_ARCHIVE" | tar -xf - -C "$OLLAMA_DIR"
	elif tar --help 2>/dev/null | grep -q -- '--zstd'; then
		tar --zstd -xf "$OLLAMA_ARCHIVE" -C "$OLLAMA_DIR"
	else
		echo "Ollama's .tar.zst archive requires zstd or tar with --zstd support" >&2
		exit 1
	fi
	rm -f "$OLLAMA_ARCHIVE"
	trap - EXIT
	OLLAMA_BIN="$OLLAMA_DIR/bin/ollama"
fi
[ -x "$OLLAMA_BIN" ] || { echo "Ollama binary was not installed at $OLLAMA_BIN" >&2; exit 1; }
say "Using ollama binary: $OLLAMA_BIN"
mkdir -p "$OLLAMA_DIR"

# --- 2. Start the server bound to localhost if it is not running ----------
export OLLAMA_HOST="$OLLAMA_HOST_ADDR"
if ! curl -fsS "http://$OLLAMA_HOST_ADDR/api/version" >/dev/null 2>&1; then
	say "Starting ollama serve on $OLLAMA_HOST_ADDR (log: $LOG_FILE)"
	nohup "$OLLAMA_BIN" serve >"$LOG_FILE" 2>&1 &
	for _ in $(seq 1 30); do
		sleep 1
		curl -fsS "http://$OLLAMA_HOST_ADDR/api/version" >/dev/null 2>&1 && break
	done
fi
curl -fsS "http://$OLLAMA_HOST_ADDR/api/version" >/dev/null 2>&1 \
	|| { echo "ollama server failed to start; see $LOG_FILE" >&2; exit 1; }
say "Server up: $(curl -fsS "http://$OLLAMA_HOST_ADDR/api/version")"

# --- 3. Choose a base model tag by VRAM unless MODEL_TAG is set -----------
if [ -z "${MODEL_TAG:-}" ]; then
	VRAM_MB="$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | sort -nr | head -1 || echo 0)"
	say "Detected GPU VRAM: ${VRAM_MB} MiB"
	# Quantized 27B weights plus runtime/context overhead need roughly a 24 GB
	# card. A 16 GB card should start at 9B rather than silently CPU-offloading
	# a successfully downloaded 27B model.
	if [ "$VRAM_MB" -ge 22000 ]; then
		CANDIDATES="qwen3.5:27b qwen3.5:9b qwen3.5:4b"
	elif [ "$VRAM_MB" -ge 12000 ]; then
		CANDIDATES="qwen3.5:9b qwen3.5:4b"
	else
		CANDIDATES="qwen3.5:4b"
	fi
else
	CANDIDATES="$MODEL_TAG"
fi

BASE_TAG=""
for tag in $CANDIDATES; do
	say "Pulling $tag"
	if "$OLLAMA_BIN" pull "$tag"; then
		BASE_TAG="$tag"
		break
	fi
	echo "Pull failed for $tag; trying next candidate" >&2
done
[ -n "$BASE_TAG" ] || { echo "No candidate model tag could be pulled: $CANDIDATES" >&2; exit 1; }

# --- 4. Create the pinned campaign model ----------------------------------
SIZE="${BASE_TAG##*:}"
CAMPAIGN_MODEL="qwen3.5-agentdojo:${SIZE}"
say "Creating $CAMPAIGN_MODEL (num_ctx $NUM_CTX)"
MODELFILE="$(mktemp)"
cat >"$MODELFILE" <<EOF
FROM $BASE_TAG

# Pin the context because Ollama's OpenAI-compatible endpoint does not accept
# context size as a standard per-request field. Must match the harness's
# thinking-profile context_tokens (agentdojo_native.py).
PARAMETER num_ctx $NUM_CTX
EOF
"$OLLAMA_BIN" create "$CAMPAIGN_MODEL" -f "$MODELFILE"
rm -f "$MODELFILE"

say "Done. Campaign model: $CAMPAIGN_MODEL"
"$OLLAMA_BIN" list
cat <<EOF

Next, from the laptop:
  1. Forward the port over the existing control socket:
       ssh -S /tmp/agentdojo-gpu.sock -O forward -L 11434:127.0.0.1:11434 \\
         user@gpu-host.example
  2. Smoke-test one case with the thinking profile:
       .agentdojo-venv/bin/python sentinel/evals/agentdojo_native.py agent \\
         --provider ollama --model $CAMPAIGN_MODEL --ollama-profile thinking \\
         --min-interval-s 0 --suite banking \\
         --user-task user_task_0 --injection-task injection_task_0 \\
         --skip-injection-utility --pretty
EOF
