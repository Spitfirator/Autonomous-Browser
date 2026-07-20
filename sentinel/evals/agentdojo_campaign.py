#!/usr/bin/env python3
"""Run the complete AgentDojo matrix as a resumable paired campaign.

Each off/enforce execution is launched in an isolated subprocess and written to
an atomic per-case report. Existing native-agent reports are discovered by
their contents, so the campaign resumes across old batches and new checkpoint
files without relying on filenames. Daily Gemini quota exhaustion either stops
cleanly or waits until the documented midnight-Pacific reset.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from itertools import zip_longest
from pathlib import Path
from typing import Any, Literal
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[2]
SENTINEL_DIR = ROOT / 'sentinel'
NATIVE_RUNNER = Path(__file__).with_name('agentdojo_native.py')

Mode = Literal['off', 'enforce']
MODES: tuple[Mode, ...] = ('off', 'enforce')
PRIORITY_INJECTIONS = {
	'workspace': 'injection_task_0',
	'travel': 'injection_task_0',
	'banking': 'injection_task_0',
	'slack': 'injection_task_1',
}
DAILY_QUOTA_MARKERS = (
	'GenerateRequestsPerDayPerProjectPerModel-FreeTier',
	'generate_content_free_tier_requests',
	'GenerateRequestsPerDay',
)
PROVIDER_UNAVAILABLE_MARKERS = (
	'apiconnectionerror',
	'connection error',
	'connection refused',
	'failed to connect',
	'could not connect to ollama server',
)


@dataclass(frozen=True)
class CampaignCase:
	suite: str
	user_task: str
	injection_task: str

	@property
	def key(self) -> str:
		return f'{self.suite}/{self.user_task}/{self.injection_task}'


@dataclass(frozen=True)
class ExecutionFailure:
	kind: Literal['daily_quota', 'transient_quota', 'provider_unavailable', 'runner_error']
	returncode: int
	summary: str


def _task_number(task_id: str) -> int:
	match = re.search(r'_(\d+)$', task_id)
	return int(match.group(1)) if match else sys.maxsize


def build_manifest(suites: Mapping[str, Any], interleave: bool = False) -> list[CampaignCase]:
	"""Build all pairs, prioritizing the partially completed cross-suite lane.

	With ``interleave``, the remaining pairs round-robin across suites so a
	deadline-truncated campaign still covers every suite evenly instead of
	exhausting them in suite order.
	"""

	suite_names = list(suites)
	priority: list[CampaignCase] = []
	all_user_numbers = sorted(
		{
			_task_number(task_id)
			for suite in suites.values()
			for task_id in suite.user_tasks
		}
	)
	for number in all_user_numbers:
		user_task = f'user_task_{number}'
		for suite_name in suite_names:
			suite = suites[suite_name]
			injection_task = PRIORITY_INJECTIONS.get(suite_name)
			if (
				user_task in suite.user_tasks
				and injection_task is not None
				and injection_task in suite.injection_tasks
			):
				priority.append(CampaignCase(suite_name, user_task, injection_task))

	per_suite = {
		suite_name: [
			CampaignCase(suite_name, user_task, injection_task)
			for user_task in sorted(suite.user_tasks, key=_task_number)
			for injection_task in sorted(suite.injection_tasks, key=_task_number)
		]
		for suite_name, suite in suites.items()
	}
	if interleave:
		remaining = [
			case
			for group in zip_longest(*per_suite.values())
			for case in group
			if case is not None
		]
	else:
		remaining = [case for cases in per_suite.values() for case in cases]
	seen: set[CampaignCase] = set()
	manifest: list[CampaignCase] = []
	for case in [*priority, *remaining]:
		if case not in seen:
			seen.add(case)
			manifest.append(case)
	return manifest


def report_completions(
	paths: Iterable[Path],
	*,
	provider: str,
	model: str,
	attack: str,
	suite_version: str,
	approval_mode: str,
	ollama_profile: str | None = None,
) -> dict[tuple[Mode, str], Path]:
	"""Return valid completed executions found in privacy-preserving reports."""

	completed: dict[tuple[Mode, str], Path] = {}
	for path in sorted(set(paths)):
		try:
			report = json.loads(path.read_text())
		except (OSError, ValueError, TypeError):
			continue
		if report.get('kind') != 'agentdojo-native-agent-run':
			continue
		provenance = report.get('provenance', {})
		if any(
			(
				provenance.get('provider') != provider,
				provenance.get('model') != model,
				provenance.get('attack') != attack,
				provenance.get('suite_version') != suite_version,
				provenance.get('approval_mode') != approval_mode,
			)
		):
			continue
		if ollama_profile is not None:
			# Reports written before driver profiles existed used the settings
			# now named `nonthinking`, so treat a missing profile as that one.
			settings = provenance.get('model_settings') or {}
			if settings.get('profile', 'nonthinking') != ollama_profile:
				continue
		mode = provenance.get('policy', {}).get('mode')
		if mode not in MODES:
			continue
		results = report.get('results', {})
		utility = results.get('utility', {})
		attacks = results.get('attack_success', {})
		for key, passed in utility.items():
			if isinstance(passed, bool) and isinstance(attacks.get(key), bool):
				completed[(mode, key)] = path
	return completed


def campaign_report_path(directory: Path, case: CampaignCase, mode: Mode) -> Path:
	return directory / case.suite / f'{case.user_task}--{case.injection_task}--{mode}.json'


def seconds_until_daily_reset(now: datetime | None = None, buffer_s: int = 120) -> int:
	"""Return seconds until just after midnight in the Pacific quota timezone."""

	current = now or datetime.now(timezone.utc)
	pacific = current.astimezone(ZoneInfo('America/Los_Angeles'))
	next_day = pacific.date() + timedelta(days=1)
	reset = datetime.combine(next_day, datetime.min.time(), tzinfo=pacific.tzinfo) + timedelta(seconds=buffer_s)
	return max(1, int((reset - pacific).total_seconds()))


def classify_failure(returncode: int, stderr: str) -> ExecutionFailure:
	if any(marker in stderr for marker in DAILY_QUOTA_MARKERS):
		return ExecutionFailure('daily_quota', returncode, 'Gemini daily request quota exhausted')
	if '429' in stderr or 'RESOURCE_EXHAUSTED' in stderr:
		return ExecutionFailure('transient_quota', returncode, 'temporary provider quota exhausted')
	if any(marker in stderr.lower() for marker in PROVIDER_UNAVAILABLE_MARKERS):
		return ExecutionFailure('provider_unavailable', returncode, 'model provider is unavailable')
	lines = [line.strip() for line in stderr.splitlines() if line.strip()]
	summary = lines[-1][:500] if lines else f'runner exited with status {returncode}'
	return ExecutionFailure('runner_error', returncode, summary)


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	serialized = json.dumps(payload, indent=2, sort_keys=True) + '\n'
	temporary = path.with_name(f'.{path.name}.{os.getpid()}.{time.time_ns()}.tmp')
	with temporary.open('x') as handle:
		handle.write(serialized)
		handle.flush()
		os.fsync(handle.fileno())
	try:
		os.replace(temporary, path)
	except PermissionError as exc:
		if exc.errno not in (errno.EACCES, errno.EPERM):
			raise
		# Some macOS app-sandbox combinations attach a com.apple.macl xattr to
		# temporary files and reject rename(2), even though both files are owned
		# by the same user. The checkpoint is fully reconstructable from atomic
		# per-execution reports, so fall back to an fsynced in-place refresh.
		with path.open('w') as handle:
			handle.write(serialized)
			handle.flush()
			os.fsync(handle.fileno())
	finally:
		temporary.unlink(missing_ok=True)


def _discover_report_paths(existing_dir: Path, reports_dir: Path) -> set[Path]:
	paths = set(existing_dir.glob('agentdojo-e2e-*.json'))
	if reports_dir.exists():
		paths.update(reports_dir.rglob('*.json'))
	return paths


def _state_payload(
	manifest: list[CampaignCase],
	completed: Mapping[tuple[Mode, str], Path],
	*,
	model: str,
	provider: str,
	attack: str,
	last_event: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
	complete_pairs = sum(all((mode, case.key) in completed for mode in MODES) for case in manifest)
	next_execution = next(
		(
			{'mode': mode, 'case': case.key}
			for case in manifest
			for mode in MODES
			if (mode, case.key) not in completed
		),
		None,
	)
	return {
		'schema_version': 1,
		'kind': 'agentdojo-campaign-state',
		'updated_at': datetime.now(timezone.utc).isoformat(),
		'model': model,
		'provider': provider,
		'attack': attack,
		'total_pairs': len(manifest),
		'total_executions': len(manifest) * len(MODES),
		'completed_pairs': complete_pairs,
		'completed_executions': sum(
			(mode, case.key) in completed for case in manifest for mode in MODES
		),
		'next_execution': next_execution,
		'last_event': dict(last_event) if last_event else None,
	}


def _run_execution(
	args: argparse.Namespace,
	case: CampaignCase,
	mode: Mode,
	output: Path,
) -> ExecutionFailure | None:
	policy = args.off_policy if mode == 'off' else args.enforce_policy
	temporary = output.with_suffix(output.suffix + '.partial')
	temporary.parent.mkdir(parents=True, exist_ok=True)
	if temporary.exists():
		temporary.unlink()
	command = [
		sys.executable,
		str(NATIVE_RUNNER),
		'agent',
		'--suite-version',
		args.suite_version,
		'--attack',
		args.attack,
		'--provider',
		args.provider,
		'--model',
		args.model,
		'--policy',
		str(policy),
		'--approval-mode',
		args.approval_mode,
		'--min-interval-s',
		str(args.min_interval_s),
		'--ollama-profile',
		args.ollama_profile,
		'--suite',
		case.suite,
		'--user-task',
		case.user_task,
		'--injection-task',
		case.injection_task,
		'--skip-injection-utility',
		'--output',
		str(temporary),
		'--pretty',
	]
	result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
	if result.returncode:
		if temporary.exists():
			temporary.unlink()
		return classify_failure(result.returncode, result.stderr)
	try:
		report = json.loads(temporary.read_text())
		valid = (
			report.get('kind') == 'agentdojo-native-agent-run'
			and case.key in report.get('results', {}).get('utility', {})
			and case.key in report.get('results', {}).get('attack_success', {})
		)
	except (OSError, ValueError, TypeError):
		valid = False
	if not valid:
		if temporary.exists():
			temporary.unlink()
		return ExecutionFailure('runner_error', 1, 'runner produced an invalid or incomplete report')
	os.replace(temporary, output)
	return None


def _load_suites(suite_version: str) -> Mapping[str, Any]:
	try:
		from agentdojo.task_suite.load_suites import get_suites  # noqa: PLC0415
	except ModuleNotFoundError as exc:
		raise SystemExit('Run this campaign with .agentdojo-venv/bin/python') from exc
	return get_suites(suite_version)


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--suite-version', default='v1')
	parser.add_argument('--attack', default='tool_knowledge')
	parser.add_argument('--provider', choices=('auto', 'gemini', 'groq', 'ollama'), default='gemini')
	parser.add_argument('--model', default='gemini-3.1-flash-lite')
	parser.add_argument(
		'--ollama-profile',
		choices=('nonthinking', 'thinking'),
		default='nonthinking',
		help='driver settings for --provider ollama; must match the profile of any reports being resumed',
	)
	parser.add_argument('--approval-mode', choices=('deny', 'execute'), default='deny')
	parser.add_argument('--min-interval-s', type=float, default=5.0)
	parser.add_argument('--existing-dir', type=Path, default=SENTINEL_DIR / 'evals')
	parser.add_argument('--reports-dir', type=Path, default=SENTINEL_DIR / 'evals' / 'agentdojo-campaign-v1')
	parser.add_argument('--state', type=Path, default=SENTINEL_DIR / 'evals' / 'agentdojo-campaign-v1-state.json')
	parser.add_argument('--off-policy', type=Path, default=SENTINEL_DIR / 'policies' / 'agentdojo-off-policy.json')
	parser.add_argument('--enforce-policy', type=Path, default=SENTINEL_DIR / 'policies' / 'agentdojo-policy.json')
	parser.add_argument('--wait-on-daily-quota', action='store_true')
	parser.add_argument('--max-new-executions', type=int)
	parser.add_argument('--dry-run', action='store_true')
	parser.add_argument(
		'--interleave',
		action='store_true',
		help='round-robin remaining pairs across suites (even coverage under a deadline)',
	)
	args = parser.parse_args()

	manifest = build_manifest(_load_suites(args.suite_version), interleave=args.interleave)
	completed = report_completions(
		_discover_report_paths(args.existing_dir, args.reports_dir),
		provider=args.provider,
		model=args.model,
		attack=args.attack,
		suite_version=args.suite_version,
		approval_mode=args.approval_mode,
		ollama_profile=args.ollama_profile if args.provider == 'ollama' else None,
	)
	state = _state_payload(
		manifest,
		completed,
		model=args.model,
		provider=args.provider,
		attack=args.attack,
	)
	_atomic_write_json(args.state, state)
	print(
		f"AgentDojo campaign: {state['completed_pairs']}/{state['total_pairs']} paired cases, "
		f"{state['completed_executions']}/{state['total_executions']} executions complete"
	)
	if args.dry_run:
		print(f"Next: {state['next_execution']}")
		return 0

	new_executions = 0
	failures: list[dict[str, Any]] = []
	for case in manifest:
		for mode in MODES:
			if (mode, case.key) in completed:
				continue
			if args.max_new_executions is not None and new_executions >= args.max_new_executions:
				return 0
			output = campaign_report_path(args.reports_dir, case, mode)
			while True:
				print(f'Running {mode}: {case.key}', flush=True)
				failure = _run_execution(args, case, mode, output)
				if failure is None:
					completed[(mode, case.key)] = output
					new_executions += 1
					event = {'type': 'completed', 'mode': mode, 'case': case.key}
					_atomic_write_json(
						args.state,
						_state_payload(
							manifest,
							completed,
							model=args.model,
							provider=args.provider,
							attack=args.attack,
							last_event=event,
						),
					)
					break

				event = {
					'type': failure.kind,
					'mode': mode,
					'case': case.key,
					'summary': failure.summary,
				}
				_atomic_write_json(
					args.state,
					_state_payload(
						manifest,
						completed,
						model=args.model,
						provider=args.provider,
						attack=args.attack,
						last_event=event,
					),
				)
				if failure.kind == 'daily_quota':
					if not args.wait_on_daily_quota:
						print('Daily Gemini quota reached; checkpoint saved. Rerun after midnight Pacific.', file=sys.stderr)
						return 75
					wait_s = seconds_until_daily_reset()
					reset_at = datetime.now(timezone.utc) + timedelta(seconds=wait_s)
					print(f'Daily quota reached; waiting until {reset_at.isoformat()} before retrying.', flush=True)
					time.sleep(wait_s)
					continue
				if failure.kind == 'transient_quota':
					print('Temporary quota reached; retrying in 60 seconds.', flush=True)
					time.sleep(60)
					continue
				if failure.kind == 'provider_unavailable':
					print(
						'Model provider unavailable; checkpoint saved and no result recorded. '
						'Restart the provider, then rerun this campaign command.',
						file=sys.stderr,
					)
					return 69
				failures.append(event)
				print(f"Recorded runner error and continuing: {failure.summary}", file=sys.stderr)
				break

	final_state = _state_payload(
		manifest,
		completed,
		model=args.model,
		provider=args.provider,
		attack=args.attack,
	)
	final_state['runner_failures'] = failures
	_atomic_write_json(args.state, final_state)
	return 0 if not failures else 1


if __name__ == '__main__':
	raise SystemExit(main())
