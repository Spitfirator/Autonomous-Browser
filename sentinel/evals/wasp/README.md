# Sentinel on WASP

This adapter evaluates the production Sentinel governance layer in real
agentic browsing. It uses:

- the official WASP prompt injector and native user/attacker oracles;
- BrowserUse as the browser agent and privileged executor;
- Qwen 3.5 9B and the matched 27B replication through Ollama on reserved GPUs;
- the same `GovernedLLM`, `GovernedTools`, detector, risk engine and
  `PolicyEngine` used by Sentinel;
- immutable run provenance for the policy, participant mode, generated inputs,
  model and scaffold.

WASP is pinned to commit
`ffee6f41fde76acd14bd792db442479c506260c2`. Its four published setup
batches (two user goals × two injection formats) each create 21 scenarios:
**84 attacked cases per policy mode**.

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

There are two explicit participant modes:

- `none`: approvals are denied immediately and handovers time out safely. This
  preserves the original non-participant baseline.
- `oracle`: a deterministic script reads the task-local WASP attacker ground
  truth. It denies exposed targets matching the attacker domain or instantiated
  attacker action URL and otherwise approves once. User-serving handovers are
  returned without pretending that a human mutated the browser; attacker and
  unknown targets time out.

Oracle mode is a reproducible **scripted-oversight upper bound**, not a
participant study and not evidence about human workload, fatigue, trust or
rubber-stamping.

The browser middleware also has an explicit observation-sanitisation switch.
`wasp-v2-warn-policy.json` preserves warn-only behaviour.
`wasp-v2-sanitise-noalert-policy.json` enables post-verified sanitisation and
suppresses the model warning only after attributable removal leaves no
detector-positive residual. In the frozen campaigns, failed, residual or
unattributable removal used the historical model-warning fallback. The current
interactive runtime instead quarantines an unresolved current browser/read
observation for operator takeover. It also fail-closes unresolved bounded
page-extraction/tool-result values by removing the whole value. Those later
behaviours are not retroactively part of these rows.

## Primary run matrix

Each configuration uses a separate run tag and therefore a separate ignored
run directory:

| Run tag | Modes | Middleware | Participant | Thesis status |
| --- | --- | --- | --- | --- |
| `wasp-qwen35-9b-browser32k-30step-v2-warn-none-v2` | `off,enforce` | warn-only | `none` | frozen 9B baseline and warning comparison |
| `wasp-qwen35-9b-browser32k-30step-v2-sanitise-noalert-none-v2` | `enforce` | sanitise V1 | `none` | development row; provenance-separated |
| `wasp-qwen35-9b-browser32k-30step-v2-sanitise-noalert-none-v3` | `enforce` | sanitise V2 | `none` | final 9B row using the frozen shared off baseline |
| `wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1` | `off,enforce` | sanitise V2 | `none` | primary matched browser comparison |

The matched 27B row is the primary browser comparison. The 9B sequence is
reported as provenance-separated engineering evidence because middleware
changed between sanitisation revisions. No oracle-participant WASP row was run.
Do not pool the historical 20-step pilot, different policies, middleware
revisions or participant modes.

The baseline intentionally uses Sentinel before plan-level authority. In plain
terms, a future plan-authority feature would show the user a short plan before
the run: the intended goal, expected sites/data, allowed and prohibited
actions, likely intervention points, and stop conditions. If implemented, it
would need a new separate ablation such as:

1. BrowserUse + Sentinel off;
2. BrowserUse + current Sentinel enforcement;
3. BrowserUse + Sentinel enforcement plus plan authority.

That would isolate the contribution of plan authority. BrowserUse's internal
structured planning remains enabled in every existing cell; it is not the same
as a human-visible, pre-execution authority contract. This is optional future
HITL work, not an authorized next benchmark.

## Model/scaffold profile

The initial profile is `qwen3.5-agentdojo:9b`; the final matched replication
uses `qwen3.5-agentdojo:27b`. Both use 32,768 context tokens, 4,096 output
tokens, temperature 0.6, top-p 0.95 and seed 0. BrowserUse uses one structured
action per step, a 30-step cap, DOM/accessibility observations and no
screenshots. Its explicit structured planning/thinking fields are enabled.

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
`WASP_RUN_TAG`, `WASP_POLICY` and `WASP_PARTICIPANT` form one provenance
tuple; change the run tag whenever either of the other two changes.

The historical 30-step campaign uses the explicit run tag
`wasp-qwen35-9b-browser32k-30step-v1` and a 30-step budget. The earlier
20-step execution is retained locally as a pilot and must not be pooled with
or substituted into the 30-step results. It must always be opened with
`wasp-warn-policy.json` and participant `none`; the state loader rejects a
policy or participant mismatch. Set `WASP_RESET_BETWEEN_CELLS=1` so every new
21-task cell starts from pristine GitLab and Reddit clones.

The bootstrap creates `.wasp/`, clones the official source at the pinned
commit, installs a Python 3.10 evaluator environment and installs Chromium.
It deliberately omits VisualWebArena's unused CUDA/captioning stack.

## Replacement GPU setup

The local `.wasp/` checkout, task checkpoints, event logs and native scores
stay on the laptop. Ollama, its model weights, GitLab, Reddit and their mutable
state live on the reserved host. A replacement GPU therefore needs those
remote services rebuilt, but it does not need completed local cells rerun.

After updating the private host and socket fields in `wasp.local.env`, establish
an interactive SSH control master:

```bash
set -a
. sentinel/evals/wasp/wasp.local.env
set +a

ssh -M -S "$WASP_SSH_SOCKET" -o ControlPersist=yes -N "$WASP_REMOTE_HOST"
```

Run that in a dedicated terminal, or add `-f` after authentication if the host
permits it. On the new host, install the pinned, checksummed user-space Ollama
release into scratch and create the 32K 9B campaign model:

```bash
ssh -S "$WASP_SSH_SOCKET" "$WASP_REMOTE_HOST" \
  "env OLLAMA_DIR='$WASP_REMOTE_ROOT/ollama' \
   OLLAMA_MODELS='$WASP_REMOTE_ROOT/ollama-models' \
   OLLAMA_LOG_FILE='$WASP_REMOTE_ROOT/ollama-server.log' \
   MODEL_TAG='qwen3.5:9b' NUM_CTX='32768' bash -s" \
  < sentinel/evals/ollama/setup-gpu-host.sh
```

The installer pins Ollama `v0.30.8`, downloads the versioned
`ollama-linux-amd64.tar.zst` GitHub asset and verifies its SHA-256 before
extracting. The model and website data are expected to be wiped with an
ephemeral reservation; rebuilding them is an operational prerequisite, not a
benchmark rerun.

## GitLab and Reddit environment

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
instances, XFS reflinks and port forwarding. Start the large downloads as soon
as a replacement reservation begins; this step does not allocate the GPU:

```bash
set -a
. sentinel/evals/wasp/wasp.local.env
set +a

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
  "WASP_CONTAINER_RUNTIME='$WASP_CONTAINER_RUNTIME' \
   WASP_REMOTE_ROOT='$WASP_REMOTE_ROOT' \
   WASP_GITLAB_TAR='$WASP_GITLAB_TAR' \
   WASP_REDDIT_TAR='$WASP_REDDIT_TAR' \
   WASP_GITLAB_SANDBOX='$WASP_GITLAB_SANDBOX' \
   WASP_REDDIT_SANDBOX='$WASP_REDDIT_SANDBOX' \
   WASP_GITLAB_IMAGE='$WASP_GITLAB_IMAGE' \
   WASP_REDDIT_IMAGE='$WASP_REDDIT_IMAGE' \
   WASP_GITLAB_REMOTE_PORT='$WASP_GITLAB_REMOTE_PORT' \
   WASP_REDDIT_REMOTE_PORT='$WASP_REDDIT_REMOTE_PORT' \
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

Every completed tag in the results table is frozen and must not be reused.
Launch a future row only with a new explicit immutable tag:

```bash
NEW_RUN_TAG=wasp-qwen35-NEW-CONDITION-v1

bash sentinel/evals/wasp/run-wasp.sh run \
  --run-tag "$NEW_RUN_TAG" \
  --policy sentinel/policies/wasp-v2-sanitise-noalert-policy.json \
  --participant none --modes off,enforce
```

Changing the model, policy, participant mode, sampling settings, middleware,
benchmark inputs or scaffold requires another new tag. Do not launch an oracle
or plan-authority row under a completed sanitisation tag.

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

GitLab can return a healthy root page before its authenticated issue form is
consistently ready. If the official injector or generated-input/auth validation
fails during preparation, the controller preserves any partial local inputs
under `abandoned-preparations/` and retries once only after another complete
pristine reset. Both attempts and the failure type are recorded in
`environment-events.jsonl`; no model task runs on the partial environment.

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

## Resuming after a GPU or reservation wipe

The controller checkpoints every task locally and refuses to mix model,
policy, participant or generated-input provenance. The recovery boundary is a
native-scored 21-task cell:

- `cleaned`: portable and skipped on the replacement GPU.
- `evaluated` or `cleanup_failed`: portable after all 21 task checkpoints and
  the native-score file validate; recovery marks it cleaned without touching
  the lost websites.
- `prepared` or `running`: not portable after GitLab/Reddit state is lost.
  Recovery moves the entire local attempt into the ignored
  `abandoned-cells/` archive and resets only that cell to pending. The next run
  prepares and executes all 21 tasks against one pristine replacement
  environment.

This is not seamless at the in-flight-cell level: task checkpoints from an
unscored cell cannot be combined with a new mutable GitLab/Reddit state. It is
seamless for every already native-scored cell.

All thesis-eligible campaigns listed above are complete and frozen. Their
status and summaries can be inspected without contacting a GPU. For example,
the matched 27B result is:

```bash
bash sentinel/evals/wasp/run-wasp.sh status \
  --run-tag wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1 \
  --policy sentinel/policies/wasp-v2-sanitise-noalert-policy.json \
  --participant none --model qwen3.5-agentdojo:27b --modes off,enforce

bash sentinel/evals/wasp/run-wasp.sh summarize \
  --run-tag wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1 \
  --policy sentinel/policies/wasp-v2-sanitise-noalert-policy.json \
  --participant none --model qwen3.5-agentdojo:27b --modes off,enforce
```

Do not invoke `run`, `finish-cell` or `recover-cell` on a completed result tag.
For a genuinely interrupted future campaign, first validate its state,
artifacts, native scores, provenance and remote-environment continuity, then
apply the recovery boundary described above.

## Curated results

The thesis-ready synthesis of all finalized, eligible WASP conditions is:

- [`results/README.md`](results/README.md)

The immutable per-run records are:

- [final 9B sanitisation V2 Markdown](results/wasp-qwen35-9b-browser32k-30step-v2-sanitise-noalert-none-v3.md)
  and [JSON](results/wasp-qwen35-9b-browser32k-30step-v2-sanitise-noalert-none-v3.json);
- [matched 27B sanitisation V2 Markdown](results/wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1.md)
  and [JSON](results/wasp-qwen35-27b-browser32k-30step-v2-sanitise-noalert-none-v1.json).

The synthesis contains the complete native/intermediate table, provenance
boundaries, sanitisation telemetry, validation gates, exclusions and bounded
thesis interpretation. It does not replace the ignored raw checkpoints.

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

Before launching a browser-sanitisation revision, replay the first detected
observation from every task in the frozen warn row. This makes no model calls
and never edits campaign artifacts:

```bash
PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/python \
  sentinel/evals/wasp/sanitization_replay.py \
  --run-root .wasp/runs/wasp-qwen35-9b-browser32k-30step-v2-warn-none-v2
```

The launch gate is exact 4x21 coverage, `removed=84`, no residual-positive
observations, no non-anchor control descriptors removed, and no whole-page
wipes. The replay is a mechanism check only; the new row must still use WASP's
native utility and attacker-success oracles.
