#!/usr/bin/env python3
"""Run neutral complete-schema canaries before a final WASP campaign.

The probes do not contain WASP tasks, attacks, policies or outcome metrics.
They test only the frozen model/runtime/scaffold path and refuse to overwrite an
existing report.  A successful report is content-hashed into campaign runtime
provenance before any official episode may start.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from browser_use.agent.prompts import SystemPrompt
from browser_use.agent.views import AgentOutput
from browser_use.llm.messages import UserMessage

from evals.wasp.contract import (
	CompatibilityCanaryCase,
	CompatibilityCanaryReport,
	ModelSettings,
	atomic_write_json,
	campaign_driver_source_sha256,
	enforcement_source_sha256,
)
from evals.wasp.runner import HANDOVER_GUIDANCE, SECURITY_GUIDANCE, _load_run_config, git_revision
from server.governance import ApprovalManager, GovernedTools, HandoverManager, PolicyEngine, RunContext
from server.ollama_chat import SentinelChatOllama

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SENTINEL_ROOT = WORKSPACE_ROOT / 'sentinel'
DEFAULT_FULL_POLICY = SENTINEL_ROOT / 'policies' / 'wasp-v2-sanitise-noalert-policy.json'
DEFAULT_POLICY_ONLY = SENTINEL_ROOT / 'policies' / 'wasp-v2-nosanitise-noalert-policy.json'
SEEDS = (0, 1, 2)
CONTEXT_PROBE_CHARS = 50_000


def _http_json(url: str, timeout: float = 15.0) -> Any:
	request = urllib.request.Request(url, headers={'User-Agent': 'Sentinel-WASP-canary/1'})
	with urllib.request.urlopen(request, timeout=timeout) as response:
		return json.load(response)


def _canonical_sha256(value: Any) -> str:
	encoded = json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')
	return hashlib.sha256(encoded).hexdigest()


def _neutral_context_probe(nonce: str, target_chars: int = CONTEXT_PROBE_CHARS) -> str:
	"""Build deterministic non-benchmark state large enough to test 32K headroom."""

	prefix = (
		'<initial_user_request>Confirm the exact neutral token in the supplied synthetic '
		'state, then finish with one successful done action.</initial_user_request>\n'
		'<synthetic_browser_state>\n'
		f'neutral_token_start={nonce}-START\n'
	)
	suffix = f'neutral_token_end={nonce}-END\n</synthetic_browser_state>'
	line = (
		'Neutral local fixture: ordinary navigation metadata, no instruction, no policy, '
		'no attack, and no benchmark outcome.\n'
	)
	if target_chars <= len(prefix) + len(suffix):
		raise ValueError('context probe target is too small')
	body_length = target_chars - len(prefix) - len(suffix)
	body = (line * ((body_length // len(line)) + 1))[:body_length]
	return prefix + body + suffix


def _output_model(
	*,
	temporary_root: Path,
	condition: str,
	policy_path: Path,
	mode: str,
	settings: ModelSettings,
) -> type[AgentOutput]:
	store = _load_run_config(
		temporary_root / f'{condition}-config.json',
		policy_path,
		mode,  # type: ignore[arg-type]
		settings,
	)
	def emit(_event: Any) -> None:
		return None

	approvals = ApprovalManager(emit)
	handovers = HandoverManager(emit)
	tools = GovernedTools(
		policy=PolicyEngine(store),
		approvals=approvals,
		handovers=handovers,
		emit=emit,
		ctx=RunContext(run_id=f'compatibility-{condition}', max_llm_calls=1),
		approval_timeout_s=1.0,
		handover_timeout_s=0.05,
		exclude_actions=(
			list(store.get().policies.blocked_actions) if mode == 'enforce' else []
		),
	)
	action_model = tools.registry.create_action_model()
	return AgentOutput.type_with_custom_actions(action_model)


def build_complete_action_schema(
	*,
	full_policy: Path,
	policy_only_policy: Path,
	settings: ModelSettings,
) -> tuple[type[AgentOutput], dict[str, str]]:
	"""Build and compare the exact BrowserUse schema for all three conditions."""

	with TemporaryDirectory(prefix='sentinel-wasp-canary-') as raw_root:
		temporary_root = Path(raw_root)
		models = {
			'off': _output_model(
				temporary_root=temporary_root,
				condition='off',
				policy_path=full_policy,
				mode='off',
				settings=settings,
			),
			'policy_only': _output_model(
				temporary_root=temporary_root,
				condition='policy-only',
				policy_path=policy_only_policy,
				mode='enforce',
				settings=settings,
			),
			'full': _output_model(
				temporary_root=temporary_root,
				condition='full',
				policy_path=full_policy,
				mode='enforce',
				settings=settings,
			),
		}
		hashes = {
			condition: _canonical_sha256(model.model_json_schema())
			for condition, model in models.items()
		}
		if len(set(hashes.values())) != 1:
			raise ValueError(f'comparison conditions expose different BrowserUse schemas: {hashes}')
		return models['off'], hashes


def _runtime_identity(
	*,
	ollama_host: str,
	model: str,
	expected_ollama_version: str,
	expected_model_digest: str,
) -> tuple[str, str]:
	version_payload = _http_json(f'{ollama_host.rstrip("/")}/api/version')
	version = str(version_payload.get('version')) if isinstance(version_payload, dict) else ''
	if version != expected_ollama_version:
		raise ValueError(f'Ollama version is {version!r}, expected {expected_ollama_version!r}')
	tags_payload = _http_json(f'{ollama_host.rstrip("/")}/api/tags')
	models = tags_payload.get('models') if isinstance(tags_payload, dict) else None
	if not isinstance(models, list):
		raise ValueError('Ollama /api/tags did not return a model list')
	entry = next(
		(
			item
			for item in models
			if isinstance(item, dict) and (item.get('name') == model or item.get('model') == model)
		),
		None,
	)
	if entry is None:
		raise ValueError(f'Ollama model {model!r} is not installed')
	digest = str(entry.get('digest') or '')
	if digest != expected_model_digest:
		raise ValueError(f'Ollama model digest is {digest!r}, expected {expected_model_digest!r}')
	return version, digest


async def run_canaries(args: argparse.Namespace) -> CompatibilityCanaryReport:
	if args.output.exists():
		raise FileExistsError(f'compatibility report already exists and will not be overwritten: {args.output}')
	version, digest = _runtime_identity(
		ollama_host=args.ollama_host,
		model=args.model,
		expected_ollama_version=args.expected_ollama_version,
		expected_model_digest=args.expected_model_digest,
	)
	settings_by_seed = [
		ModelSettings(
			model=args.model,
			ollama_host=args.ollama_host,
			context_tokens=args.context_tokens,
			output_tokens=args.output_tokens,
			temperature=args.temperature,
			top_p=args.top_p,
			seed=seed,
			native_thinking=True,
			browseruse_structured_thinking=True,
			use_vision=False,
			max_steps=args.max_steps,
			max_actions_per_step=1,
		)
		for seed in SEEDS
	]
	output_model, condition_hashes = build_complete_action_schema(
		full_policy=args.full_policy,
		policy_only_policy=args.policy_only_policy,
		settings=settings_by_seed[0],
	)
	cases: list[CompatibilityCanaryCase] = []
	for settings in settings_by_seed:
		nonce = f'SENTINEL-COMPATIBILITY-SEED-{settings.seed}'
		chat = SentinelChatOllama(
			model=settings.model,
			host=settings.ollama_host,
			timeout=300,
			native_thinking=True,
			ollama_options={
				'num_ctx': settings.context_tokens,
				'num_predict': settings.output_tokens,
				'temperature': settings.temperature,
				'top_p': settings.top_p,
				'seed': settings.seed,
			},
		)
		system_message = SystemPrompt(
			max_actions_per_step=1,
			extend_system_message=HANDOVER_GUIDANCE + SECURITY_GUIDANCE,
			use_thinking=True,
			model_name=settings.model,
		).get_system_message()
		messages = [
			system_message,
			UserMessage(
				content=(
					_neutral_context_probe(nonce)
					+ '\nDo not browse or call external services. The synthetic state is the complete '
					'evidence. Return one schema-valid done action whose text contains the exact '
					'neutral token, and no other action.'
				)
			),
		]
		started = time.monotonic()
		result = await chat.ainvoke(messages, output_model)
		latency_s = time.monotonic() - started
		actions = result.completion.action
		if len(actions) != 1:
			raise ValueError(f'seed {settings.seed}: canary returned {len(actions)} actions, expected one')
		dumped = actions[0].model_dump(exclude_none=True, mode='json')
		if set(dumped) != {'done'} or not isinstance(dumped['done'], dict):
			raise ValueError(f'seed {settings.seed}: canary did not select the done action')
		done = dumped['done']
		done_text = str(done.get('text', ''))
		if (
			done.get('success') is not True
			or f'{nonce}-START' not in done_text
			or f'{nonce}-END' not in done_text
		):
			raise ValueError(f'seed {settings.seed}: canary did not preserve its neutral token')
		diagnostics = chat.diagnostics_snapshot()
		if (
			diagnostics['failure_categories']
			or diagnostics['successes'] != 1
			or diagnostics['structured_successes'] != 1
		):
			raise ValueError(f'seed {settings.seed}: canary reliability diagnostics did not pass')
		cases.append(
			CompatibilityCanaryCase(
				seed=settings.seed,
				succeeded=True,
				latency_s=latency_s,
				action_name='done',
				native_thinking_observed=diagnostics['native_thinking_responses'] == 1,
				stop_reason=result.stop_reason,
				prompt_tokens=result.usage.prompt_tokens if result.usage is not None else None,
				completion_tokens=result.usage.completion_tokens if result.usage is not None else None,
			)
		)
	report = CompatibilityCanaryReport(
		created_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
		sentinel_commit=git_revision(WORKSPACE_ROOT),
		browser_use_commit=git_revision(WORKSPACE_ROOT / 'browser-use'),
		enforcement_sha256=enforcement_source_sha256(SENTINEL_ROOT),
		campaign_driver_sha256=campaign_driver_source_sha256(SENTINEL_ROOT),
		ollama_version=version,
		model_digest=digest,
		settings_by_seed=settings_by_seed,
		action_schema_sha256=next(iter(condition_hashes.values())),
		condition_schema_sha256=condition_hashes,
		context_probe_chars=CONTEXT_PROBE_CHARS,
		cases=cases,
	)
	atomic_write_json(args.output, report)
	return report


def _parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--output', type=Path, required=True)
	parser.add_argument('--full-policy', type=Path, default=DEFAULT_FULL_POLICY)
	parser.add_argument('--policy-only-policy', type=Path, default=DEFAULT_POLICY_ONLY)
	parser.add_argument('--model', default='qwen3.5-agentdojo:27b')
	parser.add_argument('--ollama-host', default='http://127.0.0.1:11435')
	parser.add_argument('--expected-ollama-version', required=True)
	parser.add_argument('--expected-model-digest', required=True)
	parser.add_argument('--context-tokens', type=int, default=32768)
	parser.add_argument('--output-tokens', type=int, default=8192)
	parser.add_argument('--temperature', type=float, default=0.6)
	parser.add_argument('--top-p', type=float, default=0.95)
	parser.add_argument('--max-steps', type=int, default=30)
	return parser.parse_args()


def main() -> None:
	args = _parse_args()
	report = asyncio.run(run_canaries(args))
	print(report.model_dump_json(indent=2))


if __name__ == '__main__':
	main()
