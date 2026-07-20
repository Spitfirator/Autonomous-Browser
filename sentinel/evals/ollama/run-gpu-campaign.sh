#!/usr/bin/env bash
# Resumable AgentDojo campaign against a remote GPU (runs ON THE LAPTOP; the
# GPU only serves the model through an SSH tunnel's port-forward).
#
# Put site-specific values in the ignored gpu.local.env (copy
# gpu.local.env.example), or export them before launching this script.
#
# Prereq: an SSH control master to the GPU host must be up. If authentication
# is interactive, a human must establish it:
#
#   ssh -fN -M -S "$SOCKET" -o ControlPersist=12h \
#     -o ServerAliveInterval=30 -o ServerAliveCountMax=6 \
#     -o StrictHostKeyChecking=accept-new \
#     ${GPU_JUMP_HOST:+-J "$GPU_JUMP_HOST"} "$GPU_HOST"
#
# Launch (survives terminal close; laptop must stay awake — caffeinate
# prevents idle sleep while on power, but keep the lid open):
#
#   nohup caffeinate -is bash sentinel/evals/ollama/run-gpu-campaign.sh \
#     > sentinel/evals/agentdojo-campaign-v1-qwen35-27b-thinking-runner.log 2>&1 &
#
# Safe to re-run after any interruption: experiment A resumes at suite
# granularity, experiment B resumes per-execution via the controller state.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PYTHON="$ROOT/.agentdojo-venv/bin/python"
EVALS="$ROOT/sentinel/evals"

GPU_CONFIG="${GPU_CONFIG:-$SCRIPT_DIR/gpu.local.env}"
if [ -f "$GPU_CONFIG" ]; then
	# shellcheck disable=SC1090
	source "$GPU_CONFIG"
fi

SOCKET="${SOCKET:-/tmp/agentdojo-gpu.sock}"
: "${GPU_HOST:?Set GPU_HOST in the environment or $GPU_CONFIG}"
REMOTE_OLLAMA_BIN="${REMOTE_OLLAMA_BIN:-~/.local/ollama/bin/ollama}"
LOCAL_PORT="${LOCAL_PORT:-11435}"
MODEL="${MODEL:-qwen3.5-agentdojo:27b}"
PROFILE="${PROFILE:-thinking}"
MODEL_SIZE="${MODEL##*:}"
RUN_TAG="${RUN_TAG:-qwen35-${MODEL_SIZE}-${PROFILE}}"
export OLLAMA_BASE_URL="http://127.0.0.1:${LOCAL_PORT}"

DEADLINE_EPOCH="${DEADLINE_EPOCH:-}"

case "$RUN_TAG" in
	*/* | *..*) echo "RUN_TAG must be a simple path-safe name" >&2; exit 2 ;;
esac

say() { printf '\n[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }

past_deadline() { [ -n "$DEADLINE_EPOCH" ] && [ "$(date +%s)" -ge "$DEADLINE_EPOCH" ]; }

model_up() { curl -fsS --max-time 5 "$OLLAMA_BASE_URL/api/version" >/dev/null 2>&1; }

ensure_model() {
	model_up && return 0
	# Re-plumb the forward (idempotent) in case it was lost with a reconnect.
	ssh -S "$SOCKET" -O forward -L "${LOCAL_PORT}:127.0.0.1:11434" "$GPU_HOST" 2>/dev/null
	model_up && return 0
	# Forward is up but the remote server may be down; restart it remotely.
	ssh -S "$SOCKET" "$GPU_HOST" \
		"bash -c 'pgrep -f \"ollama serve\" >/dev/null || nohup $REMOTE_OLLAMA_BIN serve > ~/ollama-server.log 2>&1 &'" \
		2>/dev/null
	for _ in $(seq 1 15); do
		sleep 4
		model_up && return 0
	done
	return 1
}

wait_for_model() {
	until ensure_model; do
		if past_deadline; then
			say "Deadline reached while waiting for the GPU; stopping gracefully."
			exit 0
		fi
		say "GPU model unreachable. If the SSH master died, restart it (see header). Retrying in 60s."
		sleep 60
	done
}

# --- Experiment A: clean-utility ceiling (no injections, off policy) -------
for suite in banking slack travel workspace; do
	out="$EVALS/agentdojo-baseline-${RUN_TAG}-clean-${suite}.json"
	if [ -s "$out" ]; then
		say "A/$suite already complete, skipping"
		continue
	fi
	if past_deadline; then
		say "Deadline reached; skipping remaining clean baselines."
		break
	fi
	wait_for_model
	say "A/$suite: clean baseline starting"
	"$PYTHON" "$EVALS/agentdojo_native.py" agent \
		--provider ollama --model "$MODEL" --ollama-profile "$PROFILE" \
		--attack none --min-interval-s 0 --suite "$suite" \
		--policy "$ROOT/sentinel/policies/agentdojo-off-policy.json" \
		--output "$out" --pretty \
		|| say "A/$suite failed (will retry on next runner invocation)"
done

# --- Experiment B: paired off/enforce campaign, suite v1, tool_knowledge ---
say "B: paired campaign starting"
while true; do
	if past_deadline; then
		say "Deadline reached; campaign stops at the last checkpoint."
		break
	fi
	wait_for_model
	"$PYTHON" "$EVALS/agentdojo_campaign.py" \
		--provider ollama --model "$MODEL" --ollama-profile "$PROFILE" \
		--min-interval-s 0 --interleave \
		--existing-dir "$EVALS" \
		--reports-dir "$EVALS/agentdojo-campaign-v1-${RUN_TAG}" \
		--state "$EVALS/agentdojo-campaign-v1-${RUN_TAG}-state.json"
	rc=$?
	if [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ]; then
		# 0 = complete; 1 = complete with recorded runner errors (no retry).
		say "B: campaign finished with exit $rc"
		break
	fi
	# 69 = provider unavailable (tunnel or remote server dropped): reconnect
	# via wait_for_model and resume from the controller checkpoint.
	say "B: controller exited $rc; resuming after reconnect"
	sleep 15
done

say "Runner done. State: $EVALS/agentdojo-campaign-v1-${RUN_TAG}-state.json"
