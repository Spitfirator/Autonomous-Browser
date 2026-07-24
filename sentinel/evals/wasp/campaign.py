"""Resumable Sentinel + BrowserUse campaign controller for official WASP."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evals.wasp.contract import (
	CampaignState,
	CampaignSummary,
	CellState,
	ModelSettings,
	NativeBatchScores,
	NativeTaskScore,
	ParticipantMode,
	PolicyMode,
	TASK_IDS,
	TaskResult,
	WASP_COMMIT,
	WASP_CONFIG,
	WaspBatch,
	aggregate_cell,
	all_batches,
	atomic_write_json,
	cell_id,
	load_json,
	sha256_file,
	enforcement_source_sha256,
	sha256_manifest,
	validate_generated_tasks,
)
from evals.wasp.runner import git_revision, run_task, validate_completed_execution

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SENTINEL_ROOT = WORKSPACE_ROOT / 'sentinel'
DEFAULT_EXTERNAL_ROOT = WORKSPACE_ROOT / '.wasp'
DEFAULT_POLICY = Path(
	os.environ.get(
		'WASP_POLICY',
		str(SENTINEL_ROOT / 'policies' / 'wasp-policy.json'),
	)
)
DEFAULT_RUN_TAG = os.environ.get(
	'WASP_RUN_TAG',
	'wasp-qwen35-9b-browser32k-30step-v1',
)
DEFAULT_MAX_STEPS = int(os.environ.get('WASP_MAX_STEPS', '30'))
DEFAULT_PARTICIPANT = os.environ.get('WASP_PARTICIPANT', 'none')


def _environment_flag(name: str, default: bool = False) -> bool:
	value = os.environ.get(name)
	if value is None:
		return default
	normalized = value.strip().lower()
	if normalized in {'1', 'true', 'yes', 'on'}:
		return True
	if normalized in {'0', 'false', 'no', 'off'}:
		return False
	raise ValueError(f'{name} must be one of 1/0, true/false, yes/no, or on/off')


DEFAULT_RESET_BETWEEN_CELLS = _environment_flag('WASP_RESET_BETWEEN_CELLS')
DEFAULT_RESET_SCRIPT = Path(
	os.environ.get(
		'WASP_RESET_SCRIPT',
		str(Path(__file__).with_name('reset-between-cells.sh')),
	)
)


def _http_json(url: str, timeout: float = 5.0) -> Any:
	request = urllib.request.Request(url, headers={'User-Agent': 'Sentinel-WASP-preflight/1'})
	with urllib.request.urlopen(request, timeout=timeout) as response:
		return json.load(response)


def _http_reachable(url: str, timeout: float = 5.0) -> None:
	request = urllib.request.Request(url, headers={'User-Agent': 'Sentinel-WASP-preflight/1'})
	try:
		with urllib.request.urlopen(request, timeout=timeout):
			return
	except urllib.error.HTTPError as exc:
		# An authenticated service can be healthy while returning 401/403.
		if exc.code in (401, 403):
			return
		raise


def _subprocess_env(wasp_root: Path, external_root: Path) -> dict[str, str]:
	env = dict(os.environ)
	python_path = [
		str(SENTINEL_ROOT),
		str(WORKSPACE_ROOT / 'browser-use'),
		str(wasp_root / 'visualwebarena'),
	]
	if env.get('PYTHONPATH'):
		python_path.append(env['PYTHONPATH'])
	env['PYTHONPATH'] = os.pathsep.join(python_path)
	env['DATASET'] = 'webarena_prompt_injections'
	env.setdefault('PLAYWRIGHT_BROWSERS_PATH', str(external_root / 'browsers'))
	env.setdefault('XDG_CACHE_HOME', str(external_root / 'cache'))
	env.setdefault('MPLCONFIGDIR', str(external_root / 'cache' / 'matplotlib'))
	env.setdefault('HF_HOME', str(external_root / 'cache' / 'huggingface'))
	env.setdefault('NLTK_DATA', str(external_root / 'nltk_data'))
	if not env.get('OPENAI_API_KEY') and not (
		env.get('AZURE_API_KEY') and env.get('AZURE_API_ENDPOINT')
	):
		# VisualWebArena imports its optional fuzzy-match OpenAI helper even
		# though WASP's program_html/exfil oracles do not call it.
		env['OPENAI_API_KEY'] = 'EMPTY'
		env['OPENAI_API_BASE'] = 'http://127.0.0.1:9/v1'
	return env


def _run_checked(
	command: list[str],
	*,
	cwd: Path,
	env: dict[str, str],
	capture: bool = False,
) -> subprocess.CompletedProcess[str]:
	return subprocess.run(
		command,
		cwd=cwd,
		env=env,
		check=True,
		text=True,
		capture_output=capture,
	)


class WaspCampaign:
	def __init__(self, args: argparse.Namespace) -> None:
		self.args = args
		self.external_root = args.external_root.resolve()
		self.wasp_root = (args.wasp_root or self.external_root / 'vendor' / 'wasp').resolve()
		# Do not Path.resolve() a virtualenv interpreter: it follows the symlink
		# to the base Python and bypasses the venv's installed packages.
		self.venv_python = Path(
			os.path.abspath(args.venv_python or self.external_root / 'venv' / 'bin' / 'python')
		)
		self.run_root = (args.run_root or self.external_root / 'runs' / args.run_tag).resolve()
		self.policy_path = args.policy.resolve()
		self.reset_script = args.reset_script.resolve()
		self.state_path = self.run_root / 'campaign-state.json'
		self.summary_path = self.run_root / 'summary.json'
		self.environment_events_path = self.run_root / 'environment-events.jsonl'
		self.operational_failures_path = self.run_root / 'operational-failures.jsonl'
		self.settings = ModelSettings(
			model=args.model,
			ollama_host=args.ollama_host,
			max_steps=args.max_steps,
		)
		self.participant: ParticipantMode = args.participant
		self.policy_sha = sha256_file(self.policy_path)
		self.enforcement_sha = enforcement_source_sha256(SENTINEL_ROOT)
		self.env = _subprocess_env(self.wasp_root, self.external_root)
		self.env['GITLAB'] = args.gitlab
		self.env['REDDIT'] = args.reddit

	def preflight(self, *, require_services: bool = True) -> list[str]:
		checks: list[str] = []
		if not self.wasp_root.is_dir():
			raise FileNotFoundError(f'WASP checkout missing: {self.wasp_root}; run bootstrap.sh first')
		revision = git_revision(self.wasp_root)
		if revision != WASP_COMMIT:
			raise ValueError(f'WASP checkout is {revision}, expected pinned commit {WASP_COMMIT}')
		checks.append(f'WASP source pinned at {WASP_COMMIT[:12]}')

		config_path = self.wasp_root / WASP_CONFIG
		config = load_json(config_path)
		scenarios = config.get('prompt_injections_setup_config') if isinstance(config, dict) else None
		if not isinstance(scenarios, list) or len(scenarios) != len(TASK_IDS):
			raise ValueError(f'{config_path}: expected {len(TASK_IDS)} attack scenarios')
		checks.append(f'official attack matrix has {len(scenarios)} scenarios')
		if self.args.reset_between_cells:
			if not self.reset_script.is_file():
				raise FileNotFoundError(f'WASP cell reset script missing: {self.reset_script}')
			checks.append('pristine website reset enabled before each pending cell')

		if not self.venv_python.is_file():
			raise FileNotFoundError(f'WASP virtual environment missing: {self.venv_python}; run bootstrap.sh first')
		_run_checked(
			[
				str(self.venv_python),
				'-c',
				(
					'import beartype, browser_env, click, evaluate, lxml, nltk, playwright, skimage, transformers; '
					'from evaluation_harness import evaluator_list'
				),
			],
			cwd=self.wasp_root,
			env=self.env,
			capture=True,
		)
		checks.append('WASP Python environment imports successfully')

		if require_services:
			_http_reachable(self.args.gitlab)
			_http_reachable(self.args.reddit)
			checks.append(f'GitLab reachable at {self.args.gitlab}')
			checks.append(f'Reddit reachable at {self.args.reddit}')
			models = _http_json(f'{self.args.ollama_host.rstrip("/")}/api/tags')
			names = {str(item.get('name')) for item in models.get('models', [])}
			names.update(str(item.get('model')) for item in models.get('models', []))
			if self.args.model not in names:
				raise ValueError(
					f'Ollama is reachable but {self.args.model!r} is not installed; '
					f'available models: {", ".join(sorted(name for name in names if name)) or "(none)"}'
				)
			checks.append(f'Ollama model {self.args.model} is reachable')
		return checks

	def _new_state(self) -> CampaignState:
		cells: dict[str, CellState] = {}
		for batch in all_batches():
			for mode in ('off', 'enforce'):
				key = cell_id(batch, mode)
				cells[key] = CellState(
					output_dir=str(self.run_root / batch.batch_id / mode),
				)
		return CampaignState(
			run_tag=self.args.run_tag,
			model_settings=self.settings,
			policy_sha256=self.policy_sha,
			participant=self.participant,
			enforcement_sha256=self.enforcement_sha,
			cells=cells,
		)

	def load_state(self) -> CampaignState:
		if not self.state_path.is_file():
			return self._new_state()
		state = CampaignState.model_validate(load_json(self.state_path))
		if state.run_tag != self.args.run_tag:
			raise ValueError('campaign state run tag does not match command')
		if state.benchmark_commit != WASP_COMMIT:
			raise ValueError('campaign state uses a different WASP revision')
		if state.model_settings != self.settings:
			raise ValueError('campaign state uses different model settings; choose a new --run-tag')
		if state.policy_sha256 != self.policy_sha:
			raise ValueError('campaign state uses a different policy; choose a new --run-tag')
		if state.participant != self.participant:
			raise ValueError('campaign state uses a different participant mode; choose a new --run-tag')
		if state.enforcement_sha256 is None:
			# Checkpoints written before enforcement fingerprinting cannot prove
			# which middleware produced them. Adopt the current hash only when the
			# run is already finished, so a frozen row stays readable.
			if any(cell.status not in ('evaluated', 'cleaned', 'cleanup_failed') for cell in state.cells.values()):
				raise ValueError(
					'campaign state predates enforcement fingerprinting and is unfinished; '
					'choose a new --run-tag rather than resuming it'
				)
		elif state.enforcement_sha256 != self.enforcement_sha:
			raise ValueError(
				'campaign state was produced by different enforcement middleware; choose a new --run-tag'
			)
		return state

	def save_state(self, state: CampaignState) -> None:
		atomic_write_json(self.state_path, state)

	def _append_jsonl(self, path: Path, event: dict[str, Any]) -> None:
		self.run_root.mkdir(parents=True, exist_ok=True)
		with path.open('a', encoding='utf-8') as handle:
			handle.write(json.dumps(event, sort_keys=True) + '\n')

	def _cell(self, state: CampaignState, batch: WaspBatch, mode: PolicyMode) -> tuple[str, CellState, Path]:
		key = cell_id(batch, mode)
		cell = state.cells[key]
		return key, cell, Path(cell.output_dir)

	def _cell_from_key(
		self,
		state: CampaignState,
		key: str,
	) -> tuple[WaspBatch, PolicyMode, CellState, Path]:
		if key not in state.cells:
			known = ', '.join(sorted(state.cells))
			raise ValueError(f'unknown cell {key!r}; choose one of: {known}')
		batch_id, raw_mode = key.rsplit('/', 1)
		if raw_mode not in ('off', 'enforce'):
			raise ValueError(f'invalid cell policy mode in {key!r}')
		mode: PolicyMode = raw_mode  # type: ignore[assignment]
		batch = next((candidate for candidate in all_batches() if candidate.batch_id == batch_id), None)
		if batch is None:
			raise ValueError(f'invalid WASP batch in {key!r}')
		cell = state.cells[key]
		return batch, mode, cell, Path(cell.output_dir)

	def _validate_task_provenance(
		self,
		result: TaskResult,
		batch: WaspBatch,
		mode: PolicyMode,
		task_id: int,
	) -> None:
		if (
			result.case_id != batch.case_id(task_id)
			or result.batch_id != batch.batch_id
			or result.task_id != task_id
			or result.policy_mode != mode
			or result.provenance.policy_mode != mode
		):
			raise ValueError(f'{batch.case_id(task_id)}: task checkpoint cell provenance mismatch')
		if result.provenance.policy_sha256 != self.policy_sha:
			raise ValueError(f'{batch.case_id(task_id)}: task checkpoint policy mismatch')
		if result.provenance.model_settings != self.settings:
			raise ValueError(f'{batch.case_id(task_id)}: task checkpoint model settings mismatch')
		if result.provenance.participant != self.participant:
			raise ValueError(f'{batch.case_id(task_id)}: task checkpoint participant mismatch')
		if (
			result.provenance.enforcement_sha256 is not None
			and result.provenance.enforcement_sha256 != self.enforcement_sha
		):
			raise ValueError(f'{batch.case_id(task_id)}: task checkpoint enforcement middleware mismatch')

	def _validate_task_checkpoint(
		self,
		result: TaskResult,
		batch: WaspBatch,
		mode: PolicyMode,
		task_id: int,
	) -> None:
		self._validate_task_provenance(result, batch, mode, task_id)
		validate_completed_execution(result)

	@staticmethod
	def _generated_input_manifest(cell_dir: Path) -> str:
		paths = [
			*(cell_dir / 'webarena_tasks' / f'{task_id}.json' for task_id in TASK_IDS),
			*(cell_dir / 'webarena_tasks_attacker' / f'{task_id}.json' for task_id in TASK_IDS),
			cell_dir / 'instantiated_prompt_injections_config.json',
		]
		if any(not path.is_file() for path in paths):
			raise ValueError(f'{cell_dir}: generated WASP input manifest is incomplete')
		return sha256_manifest(cell_dir, paths)

	def _refresh_auth(self) -> None:
		visual_root = self.wasp_root / 'visualwebarena'
		env = dict(self.env)
		env['PATH'] = f'{self.venv_python.parent}{os.pathsep}{env.get("PATH", "")}'
		_run_checked(['bash', 'prepare.sh'], cwd=visual_root, env=env)
		for name in ('gitlab_state.json', 'reddit_state.json'):
			if not (visual_root / '.auth' / name).is_file():
				raise FileNotFoundError(f'WASP auto-login did not create .auth/{name}')

	def _reset_environment_before_cell(self, batch: WaspBatch, mode: PolicyMode) -> None:
		if not self.args.reset_between_cells:
			return
		if not self.reset_script.is_file():
			raise FileNotFoundError(f'WASP cell reset script missing: {self.reset_script}')
		key = cell_id(batch, mode)
		print(f'Resetting pristine WASP websites before {key}.', flush=True)
		_run_checked(
			['bash', str(self.reset_script)],
			cwd=WORKSPACE_ROOT,
			env=self.env,
		)
		_http_reachable(self.args.gitlab)
		_http_reachable(self.args.reddit)
		models = _http_json(f'{self.args.ollama_host.rstrip("/")}/api/tags')
		names = {str(item.get('name')) for item in models.get('models', [])}
		names.update(str(item.get('model')) for item in models.get('models', []))
		if self.args.model not in names:
			raise ValueError(
				f'WASP cell reset completed but model {self.args.model!r} is not reachable'
			)
		event = {
			'type': 'pristine_environment_reset',
			'observed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
			'cell_id': key,
			'reset_script': str(self.reset_script),
			'gitlab': self.args.gitlab,
			'reddit': self.args.reddit,
			'ollama_host': self.args.ollama_host,
		}
		self._append_jsonl(self.environment_events_path, event)
		print(f'Pristine WASP websites verified for {key}.', flush=True)

	def _prepare_cell(
		self,
		state: CampaignState,
		batch: WaspBatch,
		mode: PolicyMode,
	) -> tuple[CellState, Path]:
		_, cell, cell_dir = self._cell(state, batch, mode)
		if cell.status != 'pending':
			validate_generated_tasks(cell_dir / 'webarena_tasks', batch)
			validate_generated_tasks(cell_dir / 'webarena_tasks_attacker', batch)
			manifest = self._generated_input_manifest(cell_dir)
			if cell.input_manifest_sha256 is not None and cell.input_manifest_sha256 != manifest:
				raise ValueError(f'{cell_dir}: generated WASP input manifest changed after preparation')
			if cell.input_manifest_sha256 is None:
				cell.input_manifest_sha256 = manifest
				self.save_state(state)
			return cell, cell_dir
		if cell_dir.exists() and any(cell_dir.iterdir()):
			raise RuntimeError(
				f'{cell_dir} already contains data but its checkpoint is pending. '
				'Move it aside or use a new --run-tag; the controller will not delete evidence.'
			)
		self._reset_environment_before_cell(batch, mode)
		cell_dir.mkdir(parents=True, exist_ok=True)
		injector_root = self.wasp_root / 'webarena_prompt_injections'
		_run_checked(
			[
				str(self.venv_python),
				'prompt_injector.py',
				'--config',
				str(self.wasp_root / WASP_CONFIG),
				'--gitlab-domain',
				self.args.gitlab,
				'--reddit-domain',
				self.args.reddit,
				'--model',
				'gpt-4o-mini',
				'--user_goal_idx',
				str(batch.user_goal_index),
				'--injection_format',
				batch.injection_format,
				'--output-dir',
				str(cell_dir),
				'--output-format',
				'gpt_web_tools',
			],
			cwd=injector_root,
			env=self.env,
		)
		validate_generated_tasks(cell_dir / 'webarena_tasks', batch)
		validate_generated_tasks(cell_dir / 'webarena_tasks_attacker', batch)
		cell.input_manifest_sha256 = self._generated_input_manifest(cell_dir)
		self._refresh_auth()
		cell.status = 'prepared'
		cell.last_error = None
		self.save_state(state)
		return cell, cell_dir

	async def _run_tasks(
		self,
		state: CampaignState,
		batch: WaspBatch,
		mode: PolicyMode,
		cell: CellState,
		cell_dir: Path,
	) -> None:
		cell.status = 'running'
		self.save_state(state)
		log_dir = cell_dir / 'agent_logs'
		log_dir.mkdir(exist_ok=True)
		for task_id in TASK_IDS:
			task_dir = cell_dir / 'tasks' / f'task-{task_id}'
			result_path = task_dir / 'task-result.json'
			if task_id in cell.completed_task_ids:
				result = TaskResult.model_validate(load_json(result_path))
				self._validate_task_checkpoint(result, batch, mode, task_id)
				continue
			try:
				await run_task(
					task_path=cell_dir / 'webarena_tasks' / f'{task_id}.json',
					task_dir=task_dir,
					batch=batch,
					mode=mode,
					settings=self.settings,
					policy_path=self.policy_path,
					wasp_root=self.wasp_root,
					workspace_root=WORKSPACE_ROOT,
					participant=self.participant,
					attacker_task_path=cell_dir / 'webarena_tasks_attacker' / f'{task_id}.json',
					injection_config_path=cell_dir / 'instantiated_prompt_injections_config.json',
				)
				source_log = task_dir / 'agent-logs' / f'{task_id}.jsonl'
				shutil.copy2(source_log, log_dir / source_log.name)
			except BaseException as exc:
				cell.last_error = type(exc).__name__
				self.save_state(state)
				raise
			cell.completed_task_ids = sorted({*cell.completed_task_ids, task_id})
			cell.last_error = None
			self.save_state(state)

	def _native_evaluate(
		self,
		state: CampaignState,
		batch: WaspBatch,
		mode: PolicyMode,
		cell: CellState,
		cell_dir: Path,
	) -> None:
		output = cell_dir / 'native-scores.json'
		_run_checked(
			[
				str(self.venv_python),
				str(Path(__file__).with_name('native_eval.py')),
				'--batch-id',
				batch.batch_id,
				'--mode',
				mode,
				'--user-task-dir',
				str(cell_dir / 'webarena_tasks'),
				'--attacker-task-dir',
				str(cell_dir / 'webarena_tasks_attacker'),
				'--log-dir',
				str(cell_dir / 'agent_logs'),
				'--output',
				str(output),
			],
			cwd=self.wasp_root / 'visualwebarena',
			env=self.env,
		)
		NativeBatchScores.model_validate(load_json(output))
		cell.native_scores_file = str(output)
		cell.status = 'evaluated'
		cell.last_error = None
		self.save_state(state)
		self._optional_intermediate_evaluate(cell_dir)

	def _optional_intermediate_evaluate(self, cell_dir: Path) -> None:
		model = os.environ.get('WASP_INTERMEDIATE_CLASSIFIER_MODEL')
		has_key = bool(
			os.environ.get('OPENAI_API_KEY')
			or (os.environ.get('AZURE_API_KEY') and os.environ.get('AZURE_API_ENDPOINT'))
		)
		if not model or not has_key:
			return
		temporary_result = Path('/tmp/run_step_by_step_asr.json')
		temporary_result.unlink(missing_ok=True)
		_run_checked(
			[
				str(self.venv_python),
				'evaluator_step_by_step.py',
				'--log-folder',
				str(cell_dir / 'agent_logs'),
				'--task-folder',
				str(cell_dir / 'webarena_tasks'),
				'--format',
				'gpt_web_tools',
				'--model',
				model,
			],
			cwd=self.wasp_root / 'webarena_prompt_injections',
			env=self.env,
		)
		if temporary_result.is_file():
			shutil.copy2(temporary_result, cell_dir / 'intermediate-action-scores.json')

	def _cleanup(
		self,
		state: CampaignState,
		batch: WaspBatch,
		mode: PolicyMode,
		cell: CellState,
		cell_dir: Path,
	) -> None:
		try:
			_run_checked(
				[
					str(self.venv_python),
					'environment_cleanup.py',
					'--prompt-injection-config-path',
					str(cell_dir / 'instantiated_prompt_injections_config.json'),
					'--gitlab-domain',
					self.args.gitlab,
					'--reddit-domain',
					self.args.reddit,
				],
				cwd=self.wasp_root / 'webarena_prompt_injections',
				env=self.env,
			)
		except BaseException as exc:
			cell.status = 'cleanup_failed'
			cell.last_error = type(exc).__name__
			self.save_state(state)
			self._append_jsonl(
				self.operational_failures_path,
				{
					'type': 'cell_cleanup_failed',
					'observed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
					'cell_id': cell_id(batch, mode),
					'error_type': type(exc).__name__,
				},
			)
			raise
		cell.status = 'cleaned'
		cell.last_error = None
		self.save_state(state)

	def _recover_cleanup_failure(
		self,
		state: CampaignState,
		batch: WaspBatch,
		mode: PolicyMode,
		cell: CellState,
	) -> None:
		"""Replace failed post-evaluation cleanup with a verified pristine reset.

		Cleanup is operational hygiene and happens only after native scoring. A
		full restore from the immutable website archives is stronger than the
		benchmark's best-effort UI cleanup, but recovery is permitted only when
		the complete task and native-score checkpoints are already present.
		"""
		key = cell_id(batch, mode)
		if not self.args.reset_between_cells:
			raise RuntimeError(
				f'{key} cleanup previously failed and pristine reset recovery is disabled'
			)
		if cell.completed_task_ids != list(TASK_IDS):
			raise RuntimeError(
				f'{key} cleanup recovery refused: completed task checkpoint is incomplete'
			)
		if not cell.native_scores_file:
			raise RuntimeError(f'{key} cleanup recovery refused: native scores are missing')
		native_path = Path(cell.native_scores_file)
		native = NativeBatchScores.model_validate(load_json(native_path))
		if native.batch_id != batch.batch_id or native.policy_mode != mode:
			raise RuntimeError(f'{key} cleanup recovery refused: native-score provenance mismatch')

		previous_error = cell.last_error
		print(
			f'Recovering {key} cleanup failure with a verified pristine website reset.',
			flush=True,
		)
		try:
			self._reset_environment_before_cell(batch, mode)
		except BaseException as exc:
			self._append_jsonl(
				self.operational_failures_path,
				{
					'type': 'cleanup_recovery_reset_failed',
					'observed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
					'cell_id': key,
					'original_error_type': previous_error,
					'error_type': type(exc).__name__,
				},
			)
			raise

		self._append_jsonl(
			self.environment_events_path,
			{
				'type': 'cleanup_failure_recovered_by_pristine_reset',
				'observed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
				'cell_id': key,
				'original_error_type': previous_error,
				'native_scores_file': str(native_path),
			},
		)
		cell.status = 'cleaned'
		cell.last_error = None
		self.save_state(state)
		print(f'Recovered {key}; completed task and native-score evidence was preserved.', flush=True)

	def recover_cell_after_environment_loss(self, key: str) -> None:
		"""Recover one cell after its remote mutable websites were destroyed.

		Native scores make an evaluated cell portable, so it can be finalized
		without touching the lost websites. A prepared/running cell is not
		portable: its local evidence is archived and the entire 21-task cell is
		reset to pending for a pristine rerun on the replacement host.
		"""

		state = self.load_state()
		batch, mode, cell, cell_dir = self._cell_from_key(state, key)

		if cell.status == 'cleaned':
			print(f'{key} is already cleaned; its scored evidence is portable.')
			return
		if cell.status in ('evaluated', 'cleanup_failed'):
			if cell.completed_task_ids != list(TASK_IDS):
				raise RuntimeError(f'{key}: cannot preserve evaluated cell with incomplete task checkpoints')
			if not cell.native_scores_file:
				raise RuntimeError(f'{key}: cannot preserve evaluated cell without native scores')
			native_path = Path(cell.native_scores_file)
			native = NativeBatchScores.model_validate(load_json(native_path))
			if native.batch_id != batch.batch_id or native.policy_mode != mode:
				raise RuntimeError(f'{key}: native-score provenance mismatch')
			for task_id in TASK_IDS:
				result = TaskResult.model_validate(
					load_json(cell_dir / 'tasks' / f'task-{task_id}' / 'task-result.json')
				)
				self._validate_task_checkpoint(result, batch, mode, task_id)
			previous_status = cell.status
			cell.status = 'cleaned'
			cell.last_error = None
			self.save_state(state)
			self._append_jsonl(
				self.environment_events_path,
				{
					'type': 'evaluated_cell_preserved_after_environment_loss',
					'observed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
					'cell_id': key,
					'previous_status': previous_status,
					'native_scores_file': str(native_path),
				},
			)
			print(f'{key} was already scored; marked cleaned without rerunning it.')
			return

		if cell.status not in ('pending', 'prepared', 'running'):
			raise RuntimeError(f'{key}: unsupported recovery state {cell.status!r}')
		if cell.status == 'pending' and (not cell_dir.exists() or not any(cell_dir.iterdir())):
			print(f'{key} is already pending with no local attempt to archive.')
			return

		stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
		archive_dir = self.run_root / 'abandoned-cells' / stamp / batch.batch_id / mode
		if archive_dir.exists():
			raise FileExistsError(f'recovery archive already exists: {archive_dir}')
		archived_manifest = cell.input_manifest_sha256
		if archived_manifest is None and cell_dir.exists():
			try:
				archived_manifest = self._generated_input_manifest(cell_dir)
			except ValueError:
				# Recovery must preserve even a partially-written attempt. The
				# archive itself remains available for forensic inspection.
				archived_manifest = None
		if cell_dir.exists():
			archive_dir.parent.mkdir(parents=True, exist_ok=True)
			shutil.move(str(cell_dir), str(archive_dir))
			archived = str(archive_dir)
		else:
			archived = ''
		previous_status = cell.status
		previous_completed = list(cell.completed_task_ids)
		state.cells[key] = CellState(
			output_dir=str(cell_dir),
			restart_count=cell.restart_count + 1,
		)
		self.save_state(state)
		self._append_jsonl(
			self.environment_events_path,
			{
				'type': 'incomplete_cell_archived_after_environment_loss',
				'observed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
				'cell_id': key,
				'previous_status': previous_status,
				'completed_task_ids': previous_completed,
				'archive_dir': archived,
				'input_manifest_sha256': archived_manifest,
				'restart_count': cell.restart_count + 1,
			},
		)
		print(
			f'{key} reset to pending after remote environment loss; '
			f'previous local evidence archived at {archived or "(no directory existed)"}.'
		)

	async def finish_cell_before_environment_loss(self, key: str) -> None:
		"""Finish and native-score one cell on its original mutable websites.

		The command never advances to another cell. Zero-model checkpoints that
		performed only the runner's initial navigation are archived and retried;
		any checkpoint that could have made a model-directed mutation is kept and
		must validate normally.
		"""

		state = self.load_state()
		batch, mode, cell, cell_dir = self._cell_from_key(state, key)
		if cell.status in ('evaluated', 'cleaned', 'cleanup_failed'):
			if not cell.native_scores_file:
				raise RuntimeError(f'{key}: scored checkpoint has no native-score file')
			native = NativeBatchScores.model_validate(load_json(Path(cell.native_scores_file)))
			if native.batch_id != batch.batch_id or native.policy_mode != mode:
				raise RuntimeError(f'{key}: native-score provenance mismatch')
			print(f'{key} already has native-scored evidence; no scoring rerun is needed.')
			return
		if cell.status not in ('prepared', 'running'):
			raise RuntimeError(f'{key}: finish-cell requires a prepared or running checkpoint')

		for line in self.preflight(require_services=True):
			print(f'✓ {line}')
		cell, cell_dir = self._prepare_cell(state, batch, mode)

		retry_task_ids: list[int] = []
		for task_id in list(cell.completed_task_ids):
			result_path = cell_dir / 'tasks' / f'task-{task_id}' / 'task-result.json'
			result = TaskResult.model_validate(load_json(result_path))
			self._validate_task_provenance(result, batch, mode, task_id)
			try:
				validate_completed_execution(result)
			except ValueError:
				if (
					result.status == 'completed'
					and int(result.event_counts.get('llm_call', 0)) == 0
					and set(result.action_names).issubset({'navigate'})
				):
					retry_task_ids.append(task_id)
					continue
				raise

		if retry_task_ids:
			stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
			archive_root = (
				self.run_root
				/ 'abandoned-task-checkpoints'
				/ stamp
				/ batch.batch_id
				/ mode
			)
			for task_id in retry_task_ids:
				task_dir = cell_dir / 'tasks' / f'task-{task_id}'
				archive_task_dir = archive_root / f'task-{task_id}'
				archive_task_dir.parent.mkdir(parents=True, exist_ok=True)
				shutil.move(str(task_dir), str(archive_task_dir))
				aggregate_log = cell_dir / 'agent_logs' / f'{task_id}.jsonl'
				if aggregate_log.is_file():
					shutil.move(str(aggregate_log), str(archive_task_dir / 'aggregate-agent-log.jsonl'))
			cell.completed_task_ids = [
				task_id for task_id in cell.completed_task_ids if task_id not in retry_task_ids
			]
			cell.last_error = None
			self.save_state(state)
			self._append_jsonl(
				self.environment_events_path,
				{
					'type': 'zero_model_task_checkpoints_archived_for_same_environment_retry',
					'observed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
					'cell_id': key,
					'task_ids': retry_task_ids,
					'archive_dir': str(archive_root),
				},
			)
			print(
				f'Archived zero-model navigation-only checkpoints for {retry_task_ids}; '
				'retrying them on the same environment.',
				flush=True,
			)

		await self._run_tasks(state, batch, mode, cell, cell_dir)
		if cell.completed_task_ids != list(TASK_IDS):
			raise RuntimeError(f'{key}: finish-cell did not complete all task checkpoints')
		for task_id in TASK_IDS:
			log_path = cell_dir / 'agent_logs' / f'{task_id}.jsonl'
			if not log_path.is_file():
				raise FileNotFoundError(f'{key}: native scoring log is missing: {log_path}')
		print(f'Native-scoring {key} against its original GitLab/Reddit final state.', flush=True)
		self._native_evaluate(state, batch, mode, cell, cell_dir)
		self._cleanup(state, batch, mode, cell, cell_dir)
		print(f'{key} is native-scored and portable to a replacement GPU.', flush=True)

	async def run(self, modes: list[PolicyMode]) -> None:
		for line in self.preflight(require_services=True):
			print(f'✓ {line}')
		state = self.load_state()
		self.run_root.mkdir(parents=True, exist_ok=True)
		self.save_state(state)
		for batch in all_batches():
			for mode in modes:
				_, cell, cell_dir = self._cell(state, batch, mode)
				if cell.status == 'cleaned':
					continue
				if cell.status == 'cleanup_failed':
					self._recover_cleanup_failure(state, batch, mode, cell)
					continue
				if cell.status in ('pending', 'prepared', 'running'):
					cell, cell_dir = self._prepare_cell(state, batch, mode)
					await self._run_tasks(state, batch, mode, cell, cell_dir)
					self._native_evaluate(state, batch, mode, cell, cell_dir)
				if cell.status == 'evaluated':
					self._cleanup(state, batch, mode, cell, cell_dir)
		self.summarize(modes)

	def summarize(self, modes: list[PolicyMode] | None = None) -> CampaignSummary:
		state = self.load_state()
		selected_modes = modes or ['off', 'enforce']
		cells = []
		input_manifests: dict[str, str] = {}
		for mode in selected_modes:
			task_results: list[TaskResult] = []
			native_scores: list[NativeTaskScore] = []
			for batch in all_batches():
				key, cell, cell_dir = self._cell(state, batch, mode)
				if cell.status not in ('evaluated', 'cleaned'):
					raise RuntimeError(f'{batch.batch_id}/{mode} is not evaluated')
				manifest = cell.input_manifest_sha256 or self._generated_input_manifest(cell_dir)
				input_manifests[key] = manifest
				native = NativeBatchScores.model_validate(load_json(Path(cell.native_scores_file or '')))
				for score in native.scores:
					result = TaskResult.model_validate(
						load_json(cell_dir / 'tasks' / f'task-{score.task_id}' / 'task-result.json')
					)
					self._validate_task_checkpoint(result, batch, mode, score.task_id)
					task_results.append(result)
					native_scores.append(score)
			cells.append(aggregate_cell(mode, task_results, native_scores))
		if len(selected_modes) > 1:
			for batch in all_batches():
				batch_manifests = {
					input_manifests[cell_id(batch, mode)]
					for mode in selected_modes
				}
				if len(batch_manifests) != 1:
					raise RuntimeError(
						f'{batch.batch_id}: generated inputs differ across policy modes'
					)
		summary = CampaignSummary(
			run_tag=state.run_tag,
			model_settings=state.model_settings,
			policy_sha256=state.policy_sha256,
			cells=cells,
			participant=state.participant,
			enforcement_sha256=state.enforcement_sha256,
			input_manifests=input_manifests,
		)
		atomic_write_json(self.summary_path, summary)
		print(summary.model_dump_json(indent=2))
		return summary

	def status(self, modes: list[PolicyMode] | None = None) -> None:
		state = self.load_state()
		selected_modes = modes or ['off', 'enforce']
		print(
			f'WASP campaign [{state.run_tag}] — model {state.model_settings.model} '
			f'participant={state.participant}'
		)
		print(f'benchmark {state.benchmark_commit[:12]}  policy {state.policy_sha256[:12]}')
		print(
			'cell isolation: '
			+ ('pristine reset before pending cells' if self.args.reset_between_cells else 'manual')
		)
		print()
		valid_total = 0
		portable_total = 0
		for batch in all_batches():
			for mode in selected_modes:
				_, cell, cell_dir = self._cell(state, batch, mode)
				valid_count = 0
				for task_id in cell.completed_task_ids:
					try:
						result = TaskResult.model_validate(
							load_json(cell_dir / 'tasks' / f'task-{task_id}' / 'task-result.json')
						)
						self._validate_task_checkpoint(result, batch, mode, task_id)
						valid_count += 1
					except (OSError, ValueError):
						pass
				invalid_count = len(cell.completed_task_ids) - valid_count
				valid_total += valid_count
				is_portable = False
				if (
					cell.status in ('evaluated', 'cleaned', 'cleanup_failed')
					and valid_count == len(TASK_IDS)
					and cell.native_scores_file
				):
					try:
						native = NativeBatchScores.model_validate(
							load_json(Path(cell.native_scores_file))
						)
						is_portable = (
							native.batch_id == batch.batch_id
							and native.policy_mode == mode
						)
					except (OSError, ValueError):
						pass
				if is_portable:
					portable_total += len(TASK_IDS)
				print(
					f'{batch.batch_id:25} {mode:7} {cell.status:14} '
					f'{valid_count:2}/{len(TASK_IDS)} valid'
					+ (f'  invalid={invalid_count}' if invalid_count else '')
					+ ('  portable' if is_portable else '')
					+ (f'  restarts={cell.restart_count}' if cell.restart_count else '')
					+ (f'  error={cell.last_error}' if cell.last_error else '')
				)
		expected = len(TASK_IDS) * len(all_batches()) * len(selected_modes)
		print(f'\nvalid task checkpoints: {valid_total}/{expected}')
		print(f'portable native-scored executions: {portable_total}/{expected}')


def _common_parser(parser: argparse.ArgumentParser) -> None:
	parser.add_argument('--external-root', type=Path, default=DEFAULT_EXTERNAL_ROOT)
	parser.add_argument('--wasp-root', type=Path)
	parser.add_argument('--venv-python', type=Path)
	parser.add_argument('--run-root', type=Path)
	parser.add_argument('--run-tag', default=DEFAULT_RUN_TAG)
	parser.add_argument('--policy', type=Path, default=DEFAULT_POLICY)
	parser.add_argument('--participant', choices=('none', 'oracle'), default=DEFAULT_PARTICIPANT)
	parser.add_argument('--model', default=os.environ.get('WASP_MODEL', 'qwen3.5-agentdojo:9b'))
	parser.add_argument('--ollama-host', default=os.environ.get('WASP_OLLAMA_HOST', 'http://127.0.0.1:11435'))
	parser.add_argument('--gitlab', default=os.environ.get('GITLAB', 'http://127.0.0.1:18023'))
	parser.add_argument('--reddit', default=os.environ.get('REDDIT', 'http://127.0.0.1:19999'))
	parser.add_argument('--max-steps', type=int, default=DEFAULT_MAX_STEPS)
	parser.add_argument(
		'--reset-between-cells',
		action=argparse.BooleanOptionalAction,
		default=DEFAULT_RESET_BETWEEN_CELLS,
		help=(
			'restore pristine benchmark websites before preparing each pending 21-task cell '
			'(default: WASP_RESET_BETWEEN_CELLS)'
		),
	)
	parser.add_argument('--reset-script', type=Path, default=DEFAULT_RESET_SCRIPT)


def _parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description=__doc__)
	subparsers = parser.add_subparsers(dest='command', required=True)
	for command in ('preflight', 'run', 'status', 'summarize', 'finish-cell', 'recover-cell'):
		subparser = subparsers.add_parser(command)
		_common_parser(subparser)
		if command == 'preflight':
			subparser.add_argument('--offline', action='store_true', help='skip website and Ollama reachability')
		elif command == 'run':
			subparser.add_argument(
				'--modes',
				default='off,enforce',
				help='comma-separated policy modes (default: off,enforce)',
			)
		elif command == 'summarize':
			subparser.add_argument(
				'--modes',
				default='off,enforce',
				help='comma-separated evaluated policy modes to aggregate',
			)
		elif command == 'status':
			subparser.add_argument(
				'--modes',
				default='off,enforce',
				help='comma-separated policy modes to display',
			)
		elif command in ('finish-cell', 'recover-cell'):
			subparser.add_argument(
				'--cell',
				required=True,
				help=(
					'exact cell ID to finish or recover '
					'(for example user-goal-0-plain/enforce)'
				),
			)
	return parser.parse_args()


def _parse_modes(value: str) -> list[PolicyMode]:
	modes = [mode.strip() for mode in value.split(',') if mode.strip()]
	if not modes or any(mode not in ('off', 'enforce') for mode in modes):
		raise ValueError('--modes must contain off, enforce, or both')
	return modes  # type: ignore[return-value]


def main() -> None:
	args = _parse_args()
	campaign = WaspCampaign(args)
	if args.command == 'preflight':
		for check in campaign.preflight(require_services=not args.offline):
			print(f'✓ {check}')
	elif args.command == 'run':
		asyncio.run(campaign.run(_parse_modes(args.modes)))
	elif args.command == 'status':
		campaign.status(_parse_modes(args.modes))
	elif args.command == 'summarize':
		campaign.summarize(_parse_modes(args.modes))
	elif args.command == 'finish-cell':
		asyncio.run(campaign.finish_cell_before_environment_loss(args.cell))
	elif args.command == 'recover-cell':
		campaign.recover_cell_after_environment_loss(args.cell)


if __name__ == '__main__':
	main()
