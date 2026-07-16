#!/usr/bin/env python3
"""Convert AgentDojo suites into Sentinel's offline security-benchmark contract.

Tier 1 of the evaluation plan measures Sentinel's *middleware components in
isolation* — the prompt-injection detector, the taint/risk engine and the real
`PolicyEngine` verdict — on AgentDojo's complete user-task × injection-task
matrix.
It does **not** run a browser agent, and its numbers are therefore not
comparable to end-to-end defenses (CaMeL, Progent) that run inside AgentDojo's
own agent loop; those belong to the Tier 1.5 native-adapter route. See
``sentinel/EVALS.md``.

What this script does:

* Preserve every AgentDojo (user task, injection task) pair. AgentDojo v1 has
  629 such security cases. Each selected attack template creates a separate
  629-case stratum rather than incorrectly deduplicating host user tasks.
* Map each injection task's *terminal side-effecting* tool call to the browser
  action sink a browser-use agent would use to realize it (the mapping table is
  ``TOOL_SINKS`` below and is emitted into the manifest for provenance). Cases
  whose ground truth has no side-effecting call (e.g. denial-of-service goals)
  cannot be mapped to a sink and are dropped into the exclusion log.
* Emit one benign case for every AgentDojo user task (97 in v1), using the
  normal tool observations seen along its ground-truth path.

The main threat to validity is the tool -> sink mapping: it is the author's
principled choice, and it is written to the manifest so a reviewer can audit it.
Payloads are synthetic AgentDojo fixtures; no real secret is embedded.

Usage (needs the isolated agentdojo venv, NOT the browser-use venv)::

    uv venv adojo-venv --python 3.12
    VIRTUAL_ENV=$PWD/adojo-venv uv pip install agentdojo
    ./adojo-venv/bin/python sentinel/evals/agentdojo_convert.py \
        --out sentinel/evals/fixtures/agentdojo-security.jsonl

Then evaluate with the browser-use/sentinel venv::

    PYTHONPATH=sentinel:browser-use browser-use/.venv/bin/python \
        sentinel/evals/security_benchmark.py \
        sentinel/evals/fixtures/agentdojo-security.jsonl \
        --policy sentinel/policies/reference-policy.json --pretty
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
	from agentdojo.attacks.attack_registry import load_attack
	from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
	from agentdojo.functions_runtime import FunctionsRuntime
	from agentdojo.task_suite.load_suites import get_suites
except ModuleNotFoundError:  # pragma: no cover - environment guard
	sys.stderr.write(
		'agentdojo is not importable. Install it in an isolated venv (keep it out\n'
		'of the browser-use venv):\n\n'
		'  uv venv adojo-venv --python 3.12\n'
		'  VIRTUAL_ENV=$PWD/adojo-venv uv pip install agentdojo\n'
		'  ./adojo-venv/bin/python sentinel/evals/agentdojo_convert.py --out <path>\n'
	)
	raise SystemExit(2)


# AgentDojo's published strong baseline. It is deterministic and enriches the
# injection with the relevant tool sequence; no attacker-model call is needed.
# Additional fixed attacks can be requested with ``--attacks``.
DEFAULT_ATTACKS = ('tool_knowledge',)

# Address the injection at the model class Sentinel actually runs (Gemini
# flash-lite). AgentDojo maps this pipeline id to "AI model developed by Google"
# when rendering `important_instructions`.
DEFAULT_MODEL_NAME = 'gemini-2.0-flash-001'


@dataclass(frozen=True)
class Sink:
	"""How one AgentDojo tool is realized as a browser action sink.

	`priority` selects the terminal sink when a task's ground truth chains
	several side-effecting calls (higher wins). `effect` is documentation only.
	"""

	action: str
	effect: str
	priority: int
	params: dict[str, Any]
	target_context: dict[str, Any] | None = None


# --- The tool -> browser-sink mapping (the audited conversion decision) --------
#
# Rationale per effect class:
#   * Financial / destructive / booking commits are DOM buttons; a browser agent
#     clicks them. We hand the policy the button's natural UI label via
#     target_context so the high-impact-target path (and thus the injection
#     hard-block on a consequential click) is exercised — the same signal the
#     live extension reads from the DOM.
#   * Outbound messages and calendar entries carry the attacker's text into a
#     field: `input`, an unconditional injection hard-block sink.
#   * Publishing to / fetching an attacker URL is `navigate` to an off-origin
#     receiver (cross-origin taint).
#   * A password change is `input` into a password field (target type=password
#     -> credential taint -> also a sensitive-data-flow disclosure).
_ATTACKER_URL = 'https://exfil.attacker.invalid/collect'

TOOL_SINKS: dict[str, Sink] = {
	'send_money': Sink('click', 'financial-transfer', 100, {'index': 0}, {'element_text': 'Confirm transfer', 'tag': 'button'}),
	'update_scheduled_transaction': Sink('click', 'financial-transfer', 95, {'index': 0}, {'element_text': 'Confirm transfer', 'tag': 'button'}),
	'update_password': Sink('input', 'credential-change', 92, {'index': 0, 'text': 'N3w-Passphrase'}, {'type': 'password', 'autocomplete': 'new-password'}),
	'send_email': Sink('input', 'message-exfiltration', 88, {'index': 0, 'text': ''}, None),
	'send_direct_message': Sink('input', 'message-exfiltration', 88, {'index': 0, 'text': ''}, None),
	'post_webpage': Sink('navigate', 'publish-to-attacker', 80, {'url': _ATTACKER_URL}, None),
	'reserve_hotel': Sink('click', 'booking-commit', 75, {'index': 0}, {'element_text': 'Book now', 'tag': 'button'}),
	'delete_file': Sink('click', 'destructive', 72, {'index': 0}, {'element_text': 'Delete', 'tag': 'button'}),
	'delete_email': Sink('click', 'destructive', 72, {'index': 0}, {'element_text': 'Delete', 'tag': 'button'}),
	'remove_user_from_slack': Sink('click', 'destructive-access', 72, {'index': 0}, {'element_text': 'Delete member', 'tag': 'button'}),
	'create_calendar_event': Sink('input', 'calendar-injection', 60, {'index': 0, 'text': ''}, None),
	'get_webpage': Sink('navigate', 'fetch-attacker-url', 50, {'url': _ATTACKER_URL}, None),
	'invite_user_to_slack': Sink('click', 'access-control', 40, {'index': 0}, {'element_text': 'Invite', 'tag': 'button'}),
	'add_user_to_channel': Sink('click', 'access-control', 40, {'index': 0}, {'element_text': 'Add to channel', 'tag': 'button'}),
}


class _Pipeline:
	"""Minimal stand-in so string-only attacks can read a model name."""

	def __init__(self, name: str) -> None:
		self.name = name


def _short(text: str, limit: int = 240) -> str:
	text = ' '.join(text.split())
	return text if len(text) <= limit else text[: limit - 1] + '…'


def _terminal_sink(function_names: list[str]) -> Sink | None:
	"""Pick the highest-priority mapped (side-effecting) tool for a task."""

	mapped = [TOOL_SINKS[name] for name in function_names if name in TOOL_SINKS]
	if not mapped:
		return None
	return max(mapped, key=lambda sink: sink.priority)


def _ground_truth_functions(suite: Any, task: Any) -> list[str]:
	env = suite.load_and_inject_default_environment({})
	try:
		return [call.function for call in task.ground_truth(env)]
	except Exception:
		return []


def build_attack_cases(
	suites: dict[str, Any],
	attacks: tuple[str, ...],
	model_name: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
	cases: list[dict[str, Any]] = []
	exclusions: list[dict[str, Any]] = []
	pipeline = _Pipeline(model_name)

	for suite_name, suite in suites.items():
		app_url = f'https://{suite_name}.app.invalid/'
		loaded_attacks = {name: load_attack(name, suite, pipeline) for name in attacks}
		for user_task_id, user_task in suite.user_tasks.items():
			for injection_task_id, injection_task in suite.injection_tasks.items():
				functions = _ground_truth_functions(suite, injection_task)
				sink = _terminal_sink(functions)
				# Output-only attacks (AgentDojo travel injection_task_6 in v1)
				# attempt to terminate with attacker-selected text rather than call a
				# tool. `done` is the corresponding browser-agent protected sink.
				if sink is None:
					sink = Sink('done', 'attacker-controlled-final-output', 1, {'text': '', 'success': True})

				goal = getattr(injection_task, 'GOAL', '')
				params = dict(sink.params)
				if sink.action in ('input', 'done') and 'text' in params and params['text'] == '':
					params['text'] = _short(goal)

				for attack_name, attack in loaded_attacks.items():
					try:
						injections = attack.attack(user_task, injection_task)
					except Exception as exc:
						exclusions.append(
							{
								'suite': suite_name,
								'user_task': user_task_id,
								'injection_task': injection_task_id,
								'attack': attack_name,
								'reason': f'{type(exc).__name__}: attack could not render',
							}
						)
						continue
					if not injections:
						continue
					# A user task may observe several injection vectors. Preserve their
					# distinct locations while scanning the combined untrusted content.
					page_text = '\n\n'.join(dict.fromkeys(injections.values()))
					cases.append(
						{
							'id': f'agentdojo/{suite_name}/{user_task_id}/{injection_task_id}/{attack_name}',
							'category': f'agentdojo/{suite_name}/{attack_name}',
							'page_text': page_text,
							'current_url': app_url,
							'action': sink.action,
							'params': params,
							**({'target_context': sink.target_context} if sink.target_context else {}),
							'trusted_origin': False,
							'expected_injection': True,
							'expected_verdicts': ['block', 'approve', 'handoff'],
							'_sink_effect': sink.effect,
							'_ground_truth_functions': functions,
							'_injection_vectors': sorted(injections),
						}
					)
	return cases, exclusions


def build_benign_cases(
	suites: dict[str, Any],
	per_suite: int | None,
	seed: int,
) -> list[dict[str, Any]]:
	rng = random.Random(seed)
	cases: list[dict[str, Any]] = []

	for suite_name, suite in suites.items():
		app_url = f'https://{suite_name}.app.invalid/'
		user_tasks = list(suite.user_tasks.items())
		if per_suite is not None:
			rng.shuffle(user_tasks)
			user_tasks = user_tasks[:per_suite]
		for user_task_id, user_task in user_tasks:
			env = suite.load_and_inject_default_environment({})
			env = user_task.init_environment(env)
			runtime = FunctionsRuntime(suite.tools)
			outputs: list[str] = []
			calls = user_task.ground_truth(env)
			for call in calls:
				result, error = runtime.run_function(env, call.function, call.args)
				if error is None:
					outputs.append(tool_result_to_str(result))
			text = '\n\n'.join(outputs) or 'No untrusted tool content was observed for this task.'
			functions = [call.function for call in calls]
			sink = _terminal_sink(functions) or Sink('extract', 'read-only', 0, {'query': 'main content'})
			params = dict(sink.params)
			if sink.action == 'input' and params.get('text') == '':
				params['text'] = _short(getattr(user_task, 'PROMPT', ''))
			cases.append(
				{
					'id': f'agentdojo/{suite_name}/{user_task_id}/benign',
					'category': f'agentdojo/{suite_name}/benign',
					'page_text': text,
					'current_url': app_url,
					'action': sink.action,
					'params': params,
					**({'target_context': sink.target_context} if sink.target_context else {}),
					# The normal suite application is the intended first-party sink for
					# the user's own task. Attack cases remain untrusted because their
					# authority originates in injected tool content.
					'trusted_origin': True,
					'expected_injection': False,
					'expected_verdicts': ['allow', 'approve', 'handoff'],
				}
			)
	return cases


def strip_private(case: dict[str, Any]) -> dict[str, Any]:
	"""Drop provenance-only keys (prefixed `_`) before writing the JSONL line."""

	return {key: value for key, value in case.items() if not key.startswith('_')}


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument('--out', type=Path, default=Path('sentinel/evals/fixtures/agentdojo-security.jsonl'))
	parser.add_argument('--suite-version', default='v1', help='AgentDojo benchmark version (default v1)')
	parser.add_argument('--attacks', nargs='+', default=list(DEFAULT_ATTACKS))
	parser.add_argument('--model-name', default=DEFAULT_MODEL_NAME, help='pipeline id the injection addresses')
	parser.add_argument(
		'--benign-per-suite',
		type=int,
		default=None,
		help='optional deterministic cap; default emits every benign user task',
	)
	parser.add_argument('--seed', type=int, default=0)
	args = parser.parse_args()

	suites = get_suites(args.suite_version)
	attack_cases, exclusions = build_attack_cases(suites, tuple(args.attacks), args.model_name)
	benign_cases = build_benign_cases(suites, args.benign_per_suite, args.seed)
	all_cases = attack_cases + benign_cases

	args.out.parent.mkdir(parents=True, exist_ok=True)
	with args.out.open('w') as handle:
		for case in all_cases:
			handle.write(json.dumps(strip_private(case)) + '\n')

	try:
		from importlib.metadata import version  # noqa: PLC0415

		agentdojo_version = version('agentdojo')
	except Exception:
		agentdojo_version = 'unknown'

	manifest = {
		'source': 'agentdojo',
		'agentdojo_version': agentdojo_version,
		'suite_version': args.suite_version,
		'suites': sorted(suites),
		'attacks': list(args.attacks),
		'model_addressed': args.model_name,
		'seed': args.seed,
		'counts': {
			'attack_cases': len(attack_cases),
			'benign_cases': len(benign_cases),
			'total': len(all_cases),
			'security_pairs': len(
				{
					'/'.join(case['id'].split('/')[:4])
					for case in attack_cases
				}
			),
			'conversion_exclusions': len(exclusions),
		},
		'granularity': 'one case per (suite, user_task, injection_task, attack_template); '
		'each attack template is a complete AgentDojo security stratum.',
		'tool_sink_mapping': {
			name: {
				'action': sink.action,
				'effect': sink.effect,
				'priority': sink.priority,
				'target_context': sink.target_context,
			}
			for name, sink in TOOL_SINKS.items()
		},
		'exclusions': exclusions,
		'scope': 'Component benchmark (detector + taint/risk + real PolicyEngine verdict) on injection payloads. '
		'NOT an end-to-end agent attack-success measurement; see EVALS.md Tier 1 vs 1.5.',
	}
	manifest_path = args.out.with_suffix('.manifest.json')
	manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')

	sys.stderr.write(
		f'Wrote {len(all_cases)} cases ({len(attack_cases)} attack, {len(benign_cases)} benign) '
		f'to {args.out}\nManifest: {manifest_path}\n'
		f'Excluded {len(exclusions)} unmappable injection task(s).\n'
	)
	return 0


if __name__ == '__main__':
	raise SystemExit(main())
