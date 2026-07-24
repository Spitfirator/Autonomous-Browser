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
	validate_generated_tasks,
)
from evals.wasp.runner import git_revision, run_task, validate_completed_execution

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SENTINEL_ROOT = WORKSPACE_ROOT / 'sentinel'
DEFAULT_EXTERNAL_ROOT = WORKSPACE_ROOT / '.wasp'
DEFAULT_POLICY = SENTINEL_ROOT / 'policies' / 'wasp-policy.json'
DEFAULT_RUN_TAG = os.environ.get(
	'WASP_RUN_TAG',
	'wasp-qwen35-9b-browser32k-30step-v1',
)
DEFAULT_MAX_STEPS = int(os.environ.get('WASP_MAX_STEPS', '30'))


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
		self.policy_sha = sha256_file(self.policy_path)
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
				validate_completed_execution(result)
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
		self.summarize()

	def summarize(self) -> CampaignSummary:
		state = self.load_state()
		cells = []
		for mode in ('off', 'enforce'):
			task_results: list[TaskResult] = []
			native_scores: list[NativeTaskScore] = []
			for batch in all_batches():
				_, cell, cell_dir = self._cell(state, batch, mode)
				if cell.status not in ('evaluated', 'cleaned'):
					raise RuntimeError(f'{batch.batch_id}/{mode} is not evaluated')
				native = NativeBatchScores.model_validate(load_json(Path(cell.native_scores_file or '')))
				for score in native.scores:
					result = TaskResult.model_validate(
						load_json(cell_dir / 'tasks' / f'task-{score.task_id}' / 'task-result.json')
					)
					validate_completed_execution(result)
					task_results.append(result)
					native_scores.append(score)
			cells.append(aggregate_cell(mode, task_results, native_scores))
		summary = CampaignSummary(
			run_tag=state.run_tag,
			model_settings=state.model_settings,
			policy_sha256=state.policy_sha256,
			cells=cells,
		)
		atomic_write_json(self.summary_path, summary)
		print(summary.model_dump_json(indent=2))
		return summary

	def status(self) -> None:
		state = self.load_state()
		print(f'WASP campaign [{state.run_tag}] — model {state.model_settings.model}')
		print(f'benchmark {state.benchmark_commit[:12]}  policy {state.policy_sha256[:12]}')
		print(
			'cell isolation: '
			+ ('pristine reset before pending cells' if self.args.reset_between_cells else 'manual')
		)
		print()
		for batch in all_batches():
			for mode in ('off', 'enforce'):
				_, cell, _ = self._cell(state, batch, mode)
				print(
					f'{batch.batch_id:25} {mode:7} {cell.status:14} '
					f'{len(cell.completed_task_ids):2}/{len(TASK_IDS)} tasks'
					+ (f'  error={cell.last_error}' if cell.last_error else '')
				)
		completed = sum(
			len(cell.completed_task_ids)
			for cell in state.cells.values()
		)
		print(f'\nexecutions checkpointed: {completed}/{len(TASK_IDS) * len(all_batches()) * 2}')


def _common_parser(parser: argparse.ArgumentParser) -> None:
	parser.add_argument('--external-root', type=Path, default=DEFAULT_EXTERNAL_ROOT)
	parser.add_argument('--wasp-root', type=Path)
	parser.add_argument('--venv-python', type=Path)
	parser.add_argument('--run-root', type=Path)
	parser.add_argument('--run-tag', default=DEFAULT_RUN_TAG)
	parser.add_argument('--policy', type=Path, default=DEFAULT_POLICY)
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
	for command in ('preflight', 'run', 'status', 'summarize'):
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
	return parser.parse_args()


def main() -> None:
	args = _parse_args()
	campaign = WaspCampaign(args)
	if args.command == 'preflight':
		for check in campaign.preflight(require_services=not args.offline):
			print(f'✓ {check}')
	elif args.command == 'run':
		modes = [mode.strip() for mode in args.modes.split(',') if mode.strip()]
		if not modes or any(mode not in ('off', 'enforce') for mode in modes):
			raise ValueError('--modes must contain off, enforce, or both')
		asyncio.run(campaign.run(modes))  # type: ignore[arg-type]
	elif args.command == 'status':
		campaign.status()
	elif args.command == 'summarize':
		campaign.summarize()


if __name__ == '__main__':
	main()
