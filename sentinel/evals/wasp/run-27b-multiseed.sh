#!/usr/bin/env bash
# Replicated Qwen 3.5 27B WASP comparison and sanitisation ablation.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
LOCAL_ENV="${WASP_LOCAL_ENV:-$SCRIPT_DIR/wasp.local.env}"
LOCK_PARENT="$WORKSPACE_ROOT/.wasp/controller-locks"
LOCK_DIR="$LOCK_PARENT/qwen35-27b-multiseed-v2.lock"
mkdir -p "$LOCK_PARENT"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
	echo "Another final multiseed controller lock exists: $LOCK_DIR" >&2
	echo "Refusing to launch a duplicate controller. Inspect the existing run before removing a stale lock." >&2
	exit 19
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

if [ -f "$LOCAL_ENV" ]; then
	set -a
	# shellcheck disable=SC1090
	. "$LOCAL_ENV"
	set +a
fi

# Freeze comparison identities *after* loading machine-local connection data,
# so a stale local file cannot silently override the preregistered profile.
MODEL="qwen3.5-agentdojo:27b"
CONTEXT_TOKENS="32768"
OUTPUT_TOKENS="8192"
TEMPERATURE="0.6"
TOP_P="0.95"
SANITISE_POLICY="$WORKSPACE_ROOT/sentinel/policies/wasp-v2-sanitise-noalert-policy.json"
NOSANITISE_POLICY="$WORKSPACE_ROOT/sentinel/policies/wasp-v2-nosanitise-noalert-policy.json"
export WASP_CONTAINER_RUNTIME="singularity"
export WASP_CONTAINER_RUNTIME_VERSION="singularity-ce version 4.5.0-1.el9"
# v0.30.8 ignored Qwen 3.5's JSON schema on the non-thinking path. The final
# profile uses a release containing Ollama's merged thinking-parser/schema fix.
export WASP_OLLAMA_VERSION="0.32.5"
export WASP_MODEL_DIGEST="eeeca604a4aa3c8d0554c24fe4b8909a8dc69dc76e1044b2d8c88c37750cdffe"
export WASP_NATIVE_THINKING="true"
export WASP_CONTEXT_TOKENS="$CONTEXT_TOKENS"
export WASP_OUTPUT_TOKENS="$OUTPUT_TOKENS"
export WASP_TEMPERATURE="$TEMPERATURE"
export WASP_TOP_P="$TOP_P"
export WASP_GITLAB_IMAGE_SOURCE="http://metis.lti.cs.cmu.edu/webarena-images/gitlab-populated-final-port8023.tar"
export WASP_REDDIT_IMAGE_SOURCE="http://metis.lti.cs.cmu.edu/webarena-images/postmill-populated-exposed-withimg.tar"
export WASP_GITLAB_IMAGE_BYTES="77755595776"
export WASP_REDDIT_IMAGE_BYTES="53435097088"
export WASP_REQUIRE_ARCHIVE_VERIFICATION="1"
: "${WASP_GITLAB_IMAGE_SHA256:?Set the SHA-256 of the exact validated GitLab archive}"
: "${WASP_REDDIT_IMAGE_SHA256:?Set the SHA-256 of the exact validated Reddit archive}"
: "${WASP_SSH_SOCKET:?Set WASP_SSH_SOCKET in the local WASP environment file}"
: "${WASP_REMOTE_HOST:?Set WASP_REMOTE_HOST in the local WASP environment file}"
: "${WASP_OLLAMA_HOST:?Set WASP_OLLAMA_HOST in the local WASP environment file}"

ssh -S "$WASP_SSH_SOCKET" -O check "$WASP_REMOTE_HOST" >/dev/null
gpu_inventory="$(ssh -S "$WASP_SSH_SOCKET" "$WASP_REMOTE_HOST" \
	"nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader,nounits")"
gpu_count="$(printf '%s\n' "$gpu_inventory" | awk 'NF {count += 1} END {print count + 0}')"
[ "$gpu_count" -eq 1 ] || {
	echo "Expected exactly one reserved GPU, found $gpu_count" >&2
	exit 20
}
IFS=',' read -r gpu_name gpu_memory_total_mib gpu_driver_version <<< "$gpu_inventory"
gpu_name="$(printf '%s' "$gpu_name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
gpu_memory_total_mib="$(printf '%s' "$gpu_memory_total_mib" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
gpu_driver_version="$(printf '%s' "$gpu_driver_version" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
[[ "$gpu_memory_total_mib" =~ ^[0-9]+$ ]] && [ "$gpu_memory_total_mib" -ge 22000 ] || {
	echo "The final 27B profile requires at least 22000 MiB of GPU memory; found $gpu_memory_total_mib" >&2
	exit 21
}
export WASP_GPU_NAME="$gpu_name"
export WASP_GPU_MEMORY_TOTAL_MIB="$gpu_memory_total_mib"
export WASP_GPU_DRIVER_VERSION="$gpu_driver_version"

actual_runtime_version="$(ssh -S "$WASP_SSH_SOCKET" "$WASP_REMOTE_HOST" singularity --version)"
[ "$actual_runtime_version" = "$WASP_CONTAINER_RUNTIME_VERSION" ] || {
	echo "Singularity version drift: $actual_runtime_version" >&2
	exit 22
}
actual_ollama_version="$(curl --fail --silent --show-error --max-time 20 \
	"${WASP_OLLAMA_HOST%/}/api/version" | jq -r '.version')"
[ "$actual_ollama_version" = "$WASP_OLLAMA_VERSION" ] || {
	echo "Ollama version drift: $actual_ollama_version" >&2
	exit 23
}

CANARY_REPORT="${WASP_COMPATIBILITY_CANARY:-$WORKSPACE_ROOT/.wasp/canaries/qwen35-27b-native-thinking-output8k-v2.json}"
if [ ! -f "$CANARY_REPORT" ]; then
	printf '[%s] Running neutral complete-action-schema canaries for seeds 0, 1 and 2.\n' \
		"$(date -u +%FT%TZ)"
	PYTHONPATH="$WORKSPACE_ROOT/sentinel:$WORKSPACE_ROOT/browser-use" \
		"$WORKSPACE_ROOT/browser-use/.venv/bin/python" "$SCRIPT_DIR/compatibility.py" \
		--output "$CANARY_REPORT" \
		--full-policy "$SANITISE_POLICY" \
		--policy-only-policy "$NOSANITISE_POLICY" \
		--model "$MODEL" \
		--ollama-host "$WASP_OLLAMA_HOST" \
		--expected-ollama-version "$WASP_OLLAMA_VERSION" \
		--expected-model-digest "$WASP_MODEL_DIGEST" \
		--context-tokens "$CONTEXT_TOKENS" \
		--output-tokens "$OUTPUT_TOKENS" \
		--temperature "$TEMPERATURE" \
		--top-p "$TOP_P"
fi
export WASP_COMPATIBILITY_CANARY="$CANARY_REPORT"

loaded_row="$(curl --fail --silent --show-error --max-time 20 \
	"${WASP_OLLAMA_HOST%/}/api/ps" | jq -r --arg model "$MODEL" '
		[.models[]? | select(.name == $model or .model == $model)][0]
		| if . == null then empty
		  else [(.name // .model), .size, .size_vram, .context_length] | @tsv
		  end
	')"
[ -n "$loaded_row" ] || {
	echo "The compatibility canary did not leave $MODEL loaded in Ollama" >&2
	exit 24
}
IFS=$'\t' read -r loaded_model loaded_size loaded_size_vram loaded_context <<< "$loaded_row"
[[ "$loaded_size" =~ ^[0-9]+$ && "$loaded_size_vram" =~ ^[0-9]+$ ]] || {
	echo "Ollama did not report numeric model/VRAM sizes for $loaded_model" >&2
	exit 25
}
[ "$loaded_size" -gt 0 ] && [ "$loaded_size_vram" -eq "$loaded_size" ] || {
	echo "Model is not fully GPU-resident: size=$loaded_size size_vram=$loaded_size_vram" >&2
	exit 26
}
[ "$loaded_context" = "$CONTEXT_TOKENS" ] || {
	echo "Loaded Ollama context drift: $loaded_context (expected $CONTEXT_TOKENS)" >&2
	exit 27
}
printf '[%s] GPU=%s memory=%sMiB driver=%s; model fully resident (%s bytes); context=%s.\n' \
	"$(date -u +%FT%TZ)" "$gpu_name" "$gpu_memory_total_mib" "$gpu_driver_version" \
	"$loaded_size_vram" "$loaded_context"

run_campaign() {
	local seed="$1"
	local condition="$2"
	local policy="$3"
	local modes="$4"
	local run_tag="wasp-qwen35-27b-browser32k-output8k-30step-v2-${condition}-none-replication-seed-${seed}-v2"

	printf '\n[%s] seed=%s condition=%s modes=%s tag=%s\n' \
		"$(date -u +%FT%TZ)" "$seed" "$condition" "$modes" "$run_tag"
	bash "$SCRIPT_DIR/run-wasp.sh" run \
		--run-tag "$run_tag" \
		--policy "$policy" \
		--participant none \
		--model "$MODEL" \
		--seed "$seed" \
		--context-tokens "$CONTEXT_TOKENS" \
		--output-tokens "$OUTPUT_TOKENS" \
		--temperature "$TEMPERATURE" \
		--top-p "$TOP_P" \
		--native-thinking \
		--compatibility-canary "$CANARY_REPORT" \
		--modes "$modes"
}

bash "$SCRIPT_DIR/run-wasp.sh" preflight \
	--policy "$SANITISE_POLICY" \
	--participant none \
	--model "$MODEL" \
	--seed 0 \
	--context-tokens "$CONTEXT_TOKENS" \
	--output-tokens "$OUTPUT_TOKENS" \
	--temperature "$TEMPERATURE" \
	--top-p "$TOP_P" \
	--native-thinking \
	--compatibility-canary "$CANARY_REPORT"

for seed in 0 1 2; do
	run_campaign "$seed" "sanitise-noalert" "$SANITISE_POLICY" "off,enforce"
	run_campaign "$seed" "nosanitise-noalert" "$NOSANITISE_POLICY" "enforce"
done

RESULT_STEM="$WORKSPACE_ROOT/sentinel/evals/wasp/results/wasp-qwen35-27b-multiseed-thinking8k-replication-v2"
echo "[$(date -u +%FT%TZ)] Validating and aggregating all 756 controlled episodes."
PYTHONPATH="$WORKSPACE_ROOT/sentinel:$WORKSPACE_ROOT/browser-use" \
	"$WORKSPACE_ROOT/browser-use/.venv/bin/python" "$SCRIPT_DIR/replication.py" \
	--run-root "$WORKSPACE_ROOT/.wasp/runs" \
	--output "${RESULT_STEM}.json" \
	--markdown-output "${RESULT_STEM}.md"
echo "[$(date -u +%FT%TZ)] Replication validation and curated output complete."
