# Sentinel on WASP

This adapter evaluates the production Sentinel governance layer in real
agentic browsing. It uses:

- the official WASP prompt injector and native user/attacker oracles;
- BrowserUse as the browser agent and privileged executor;
- Qwen 3.5 9B through Ollama on the reserved GPU;
- the same `GovernedLLM`, `GovernedTools`, detector, risk engine and
  `PolicyEngine` used by Sentinel;
- paired `off` and `enforce` runs with identical tasks and model settings.

WASP is pinned to commit
`ffee6f41fde76acd14bd792db442479c506260c2`. Its four published setup
batches (two user goals × two injection formats) each create 21 scenarios:
**84 attacked cases and 168 model executions** across the two policy modes.

## Experiment contract

The primary outcomes come from WASP's native final-state oracles:

- user utility: whether the legitimate task was achieved;
- attack success rate (ASR): whether the attacker's goal was achieved;
- secure utility: legitimate task achieved without the attacker goal;
- all four joint useful/secure outcome categories.

Sentinel also records detector events, blocks, approval requests, handoffs,
action counts and enforcement latency. WASP's LLM-based intermediate-action
classifier is optional because it needs a separate OpenAI/Azure judge; it is
not required for the primary native-oracle result.

This is a non-participant benchmark. Any Sentinel approval request is denied
immediately and any handoff times out safely. This makes the run deterministic
and does not pretend to measure real human behaviour.

The baseline intentionally uses Sentinel as it exists before plan-level
authority. After the baseline is frozen, task-contract/plan authority can be
implemented and the exact same 84 cases rerun as a separate ablation:

1. BrowserUse + Sentinel off;
2. BrowserUse + current Sentinel enforcement;
3. BrowserUse + Sentinel enforcement plus plan authority.

That isolates the contribution of plan authority. BrowserUse's internal
structured planning remains enabled in every cell; the future feature is the
human-visible, pre-execution authority contract.

## Model/scaffold profile

The default profile is `qwen3.5-agentdojo:9b` with 32,768 context tokens,
4,096 output tokens, temperature 0.6, top-p 0.95 and seed 0. BrowserUse uses
one structured action per step, a 30-step cap, DOM/accessibility observations
and no screenshots. Its explicit structured planning/thinking fields are
enabled.

Ollama's separate native `think` stream is disabled because BrowserUse needs
the response body to be valid against its action schema. Do not describe this
as the same reasoning profile as the AgentDojo `thinking` runs: the WASP
experiment answers cross-environment enforcement questions, not the
4B/9B/27B parameter-scaling question.

## One-time local setup

From the repository root:

```bash
bash sentinel/evals/wasp/bootstrap.sh
```

Offline preflight, status and summarization work without private host
configuration. Before starting remote websites or a model run, create the
ignored local configuration:

```bash
cp sentinel/evals/wasp/wasp.local.env.example \
  sentinel/evals/wasp/wasp.local.env
```

Edit only the ignored `wasp.local.env`. Do not add UCL usernames, reserved
hostnames, SSH sockets, credentials or scratch paths to tracked files.

The frozen thesis campaign uses the explicit run tag
`wasp-qwen35-9b-browser32k-30step-v1` and a 30-step budget. The earlier
20-step execution is retained locally as a pilot and must not be pooled with
or substituted into the 30-step results. Set `WASP_RESET_BETWEEN_CELLS=1` in
the ignored local environment so every new 21-task cell starts from pristine
GitLab and Reddit clones.

The bootstrap creates `.wasp/`, clones the official source at the pinned
commit, installs a Python 3.10 evaluator environment and installs Chromium.
It deliberately omits VisualWebArena's unused CUDA/captioning stack.

## Website environment

WASP needs the official writable GitLab and Reddit WebArena images. The direct
official archives are approximately 72.4 GiB and 49.7 GiB respectively, so
they belong on the reserved machine's scratch volume, not the laptop and not
Git. The model uses the GPU; downloading and serving the two websites uses
disk, network, CPU and RAM.

The remote script downloads the official archives described in WASP's
`visualwebarena/environment_docker/README.md` when they are missing. With
Docker it loads the images normally. With Singularity it builds pristine
writable sandboxes and uses copy-on-write XFS clones for inexpensive resets.
The reserved remote workstation must support unprivileged Singularity
instances, XFS reflinks and port forwarding. Start the large downloads while
another model is running if desired; this step does not allocate the GPU:

```bash
scp -o ControlPath="$WASP_SSH_SOCKET" \
  sentinel/evals/wasp/remote-environment.sh \
  "$WASP_REMOTE_HOST:$WASP_REMOTE_ROOT/remote-environment.sh"

ssh -S "$WASP_SSH_SOCKET" "$WASP_REMOTE_HOST" \
  "nohup env WASP_CONTAINER_RUNTIME='$WASP_CONTAINER_RUNTIME' \
   WASP_REMOTE_ROOT='$WASP_REMOTE_ROOT' \
   bash '$WASP_REMOTE_ROOT/remote-environment.sh' download \
   >'$WASP_REMOTE_ROOT/download.log' 2>&1 </dev/null &"
```

With the existing SSH control master open:

```bash
set -a
. sentinel/evals/wasp/wasp.local.env
set +a

ssh -S "$WASP_SSH_SOCKET" "$WASP_REMOTE_HOST" \
  "WASP_GITLAB_TAR='$WASP_GITLAB_TAR' \
   WASP_REDDIT_TAR='$WASP_REDDIT_TAR' \
   WASP_GITLAB_IMAGE='$WASP_GITLAB_IMAGE' \
   WASP_REDDIT_IMAGE='$WASP_REDDIT_IMAGE' \
   WASP_PUBLIC_GITLAB_URL='$GITLAB' \
   bash -s -- start" \
  < sentinel/evals/wasp/remote-environment.sh

bash sentinel/evals/wasp/forward-ports.sh
```

The default forwards are:

| Local | Remote | Service |
| --- | --- | --- |
| `18023` | `8023` | GitLab |
| `19999` | `9999` | Reddit |
| `11435` | `11434` | Ollama |

GitLab's configured public URL must equal the URL the local browser sees
(`GITLAB`), otherwise its absolute redirects bypass the tunnel.

## Preflight and run

An offline preflight checks the pin and Python dependencies without touching
the websites or model:

```bash
bash sentinel/evals/wasp/run-wasp.sh preflight --offline
```

The full preflight additionally verifies both websites, Ollama and the exact
model tag:

```bash
bash sentinel/evals/wasp/run-wasp.sh preflight
```

Then run the paired experiment:

```bash
bash sentinel/evals/wasp/run-wasp.sh run
```

With `WASP_RESET_BETWEEN_CELLS=1`, the campaign calls
`reset-between-cells.sh` immediately before preparing each **pending** cell.
The helper restores the disposable remote website clones, restores all three
SSH forwards, waits for service health and records the successful reset in the
ignored run's `environment-events.jsonl`. This prevents Postmill's posting
cooldown from surviving from one 21-task cell into the next. A resumed
`prepared` or `running` cell is never reset, so an SSH/GPU recovery cannot
silently replace its environment halfway through the cell.

The reset is operational isolation, not an evaluation change: completed task
checkpoints, native scores, the model, step budget, policy and generated result
provenance remain untouched. If the reset itself fails, the next cell stays
pending and the injector is not started.

If the benchmark's post-evaluation UI cleanup is interrupted or fails, the
controller may recover it with the same pristine restore, but only after it
validates that all 21 task checkpoints and the complete native-score file are
already present for that cell. The recovery is appended to
`environment-events.jsonl`; cleanup and recovery failures are appended to
`operational-failures.jsonl`. This changes no score and never reruns a completed
task.

To enforce strict serialization behind the controlled 4B AgentDojo rerun,
use the queue wrapper instead. It requires the exact completed checkpoint
(629 pairs and 1,258 executions), then starts/reset the remote sites, opens the
forwards, requires a full preflight and only then launches WASP:

```bash
bash sentinel/evals/wasp/queue-after-agentdojo.sh
```

Do not run WASP model inference concurrently with an AgentDojo campaign on
the same 16 GB GPU. Both use the same Ollama server and would compete for VRAM
and throughput.

The controller is resumable. It checkpoints after every task, refuses to mix
different model/policy provenance, evaluates each 21-task cell before cleanup,
restores pristine sites before the next pending cell, and never deletes a
non-empty uncheckpointed directory. BrowserUse can return normally after
exhausting its internal retries, so the runner classifies an unfinished
history with an Ollama/provider or website connection failure as an
operational error. A completed checkpoint must contain at least one successful
model call; this prevents a lost SSH tunnel from being silently counted as a
model or policy failure. Status and aggregation make no model calls:

```bash
bash sentinel/evals/wasp/run-wasp.sh status
bash sentinel/evals/wasp/run-wasp.sh summarize
```

To run only one policy mode while diagnosing:

```bash
bash sentinel/evals/wasp/run-wasp.sh run --modes off
bash sentinel/evals/wasp/run-wasp.sh run --modes enforce
```

Use a new `--run-tag` whenever the policy, model, or scaffold settings change.

## Artifacts and publication

All source checkouts, environments, raw DOM/action logs, authentication state,
campaign checkpoints and native score files live under `.wasp/` and are
ignored. Raw traces contain synthetic benchmark page content and can be large.
Only copy a compact, reviewed `summary.json` into `sentinel/evals/` for a
publication commit, after checking its provenance.

The compact task result intentionally stores no page text, screenshots,
credentials, free-form reasoning or final-answer text. The compatible WASP
JSONL exists only in the ignored run directory.

## Tests

The integration contract can be tested without WASP, Docker, a browser or a
GPU:

```bash
PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/pytest -q \
  sentinel/tests/test_wasp_campaign.py
```
