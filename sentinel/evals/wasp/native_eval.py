"""Run WASP's native final-state user and attacker oracles for one batch.

This file must be executed with the isolated WASP virtual environment and with
``visualwebarena`` on ``PYTHONPATH``. It deliberately imports evaluator code
from the pinned official checkout instead of reimplementing benchmark oracles.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from browser_env import ScriptBrowserEnv
from evaluation_harness import evaluator_list

from evals.wasp.contract import NativeBatchScores, NativeTaskScore, TASK_IDS, WASP_COMMIT, atomic_write_json


def _score(
	env: ScriptBrowserEnv,
	config_path: Path,
	log_dir: Path,
) -> float:
	env.reset(options={'config_file': str(config_path)})
	evaluator = evaluator_list(str(config_path), str(log_dir), 'gpt_web_tools')
	last_error: Exception | None = None
	for attempt in range(3):
		try:
			return float(evaluator(trajectory=[], config_file=str(config_path), page=env.page))
		except Exception as exc:
			last_error = exc
			if attempt < 2:
				time.sleep(2)
	assert last_error is not None
	raise RuntimeError(f'WASP native evaluator failed for {config_path.name}') from last_error


def evaluate_batch(
	*,
	batch_id: str,
	mode: str,
	user_task_dir: Path,
	attacker_task_dir: Path,
	log_dir: Path,
) -> NativeBatchScores:
	env = ScriptBrowserEnv(
		headless=True,
		slow_mo=0,
		observation_type='accessibility_tree',
		current_viewport_only=True,
		viewport_size={'width': 1280, 'height': 1720},
	)
	scores: list[NativeTaskScore] = []
	try:
		for task_id in TASK_IDS:
			user_config = user_task_dir / f'{task_id}.json'
			attacker_config = attacker_task_dir / f'{task_id}.json'
			if not user_config.is_file() or not attacker_config.is_file():
				raise FileNotFoundError(f'missing official task pair for task {task_id}')
			user_utility = _score(env, user_config, log_dir)
			attacker_success = _score(env, attacker_config, log_dir)
			scores.append(
				NativeTaskScore(
					task_id=task_id,
					user_utility=user_utility,
					attacker_success=attacker_success,
				)
			)
	finally:
		env.close()
	return NativeBatchScores(
		benchmark_commit=WASP_COMMIT,
		batch_id=batch_id,
		policy_mode=mode,
		scores=scores,
	)


def _parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--batch-id', required=True)
	parser.add_argument('--mode', choices=('off', 'enforce'), required=True)
	parser.add_argument('--user-task-dir', type=Path, required=True)
	parser.add_argument('--attacker-task-dir', type=Path, required=True)
	parser.add_argument('--log-dir', type=Path, required=True)
	parser.add_argument('--output', type=Path, required=True)
	return parser.parse_args()


def main() -> None:
	args = _parse_args()
	result = evaluate_batch(
		batch_id=args.batch_id,
		mode=args.mode,
		user_task_dir=args.user_task_dir.resolve(),
		attacker_task_dir=args.attacker_task_dir.resolve(),
		log_dir=args.log_dir.resolve(),
	)
	atomic_write_json(args.output.resolve(), result)
	print(
		json.dumps(
			{
				'batch_id': result.batch_id,
				'mode': result.policy_mode,
				'tasks': len(result.scores),
				'user_utility': sum(score.user_utility for score in result.scores),
				'attacker_success': sum(score.attacker_success for score in result.scores),
			},
			indent=2,
		)
	)


if __name__ == '__main__':
	main()
