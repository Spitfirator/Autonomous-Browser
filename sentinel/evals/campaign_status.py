#!/usr/bin/env python3
"""Live status for the overnight AgentDojo GPU campaign.

Usage:
  python3 sentinel/evals/campaign_status.py            # print once
  python3 sentinel/evals/campaign_status.py --loop 60  # refresh every 60s
"""

import argparse
import calendar
import json
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path

EVALS = Path(__file__).resolve().parent
SUITES = ('banking', 'slack', 'travel', 'workspace')

# RUN_TAG selects which campaign to report; override with --tag.
RUN_TAG = 'qwen35-27b-thinking'


def state_path() -> Path:
	return EVALS / f'agentdojo-campaign-v1-{RUN_TAG}-state.json'


def reports_dir() -> Path:
	return EVALS / f'agentdojo-campaign-v1-{RUN_TAG}'


def log_path() -> Path:
	return EVALS / f'agentdojo-campaign-v1-{RUN_TAG}-runner.log'


def check(cmd: list[str]) -> bool:
	return subprocess.run(cmd, capture_output=True).returncode == 0


def current_a_suite() -> tuple[str | None, float]:
	"""Return (suite, start_epoch) for an experiment-A suite still in flight."""
	log = log_path()
	if not log.is_file():
		return None, 0.0
	for line in reversed(log.read_text().splitlines()):
		if 'clean baseline starting' in line:
			suite = line.rsplit('A/', 1)[-1].split(':', 1)[0]
			out = EVALS / f'agentdojo-baseline-{RUN_TAG}-clean-{suite}.json'
			if out.is_file() and out.stat().st_size:
				return None, 0.0  # finished; nothing in flight
			try:
				stamp = line.split(']', 1)[0].lstrip('[')
				started = calendar.timegm(time.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ'))
			except ValueError:
				started = time.time()
			return suite, started
	return None, 0.0


def main() -> None:
	global RUN_TAG
	parser = argparse.ArgumentParser()
	parser.add_argument('--loop', type=int, metavar='SECONDS')
	parser.add_argument('--tag', default=RUN_TAG, help='campaign RUN_TAG to report (e.g. qwen35-9b-thinking)')
	args = parser.parse_args()
	RUN_TAG = args.tag
	while True:
		render()
		if not args.loop:
			break
		time.sleep(args.loop)


def render() -> None:
	now = datetime.now()
	print(f'\n=== AgentDojo campaign [{RUN_TAG}] — {now:%H:%M:%S} ===')

	runner_up = check(['pgrep', '-f', 'run-gpu-campaign.sh'])
	model_up = check(['curl', '-fsS', '--max-time', '4', 'http://127.0.0.1:11435/api/version'])
	print(f'runner: {"RUNNING" if runner_up else "STOPPED"}   gpu model: {"REACHABLE" if model_up else "UNREACHABLE"}')

	in_flight, started = current_a_suite()
	print('\nA (clean ceiling, no injections):')
	for suite in SUITES:
		path = EVALS / f'agentdojo-baseline-{RUN_TAG}-clean-{suite}.json'
		if path.is_file() and path.stat().st_size:
			metrics = json.loads(path.read_text())['metrics']
			print(f'  {suite:<10} done   utility {metrics["utility_rate"]:.1%} of {metrics["cases"]} tasks')
		elif suite == in_flight:
			minutes = (time.time() - started) / 60
			print(f'  {suite:<10} RUNNING for {minutes:.0f} min (writes results when the suite finishes)')
		else:
			print(f'  {suite:<10} pending')

	state_file = state_path()
	reports = reports_dir()
	print('\nB (paired off/enforce campaign):')
	if state_file.is_file():
		state = json.loads(state_file.read_text())
		done = state['completed_executions']
		total = state['total_executions']
		print(f'  pairs {state["completed_pairs"]}/{state["total_pairs"]}   executions {done}/{total}')
		if state.get('next_execution'):
			print(f'  next: {state["next_execution"]}')
		if state.get('last_event'):
			print(f'  last event: {state["last_event"]}')
	else:
		print('  not started yet')

	if reports.is_dir():
		mtimes = sorted(p.stat().st_mtime for p in reports.glob('*/*.json'))
		counts = {s: len(list((reports / s).glob('*.json'))) for s in SUITES if (reports / s).is_dir()}
		if counts:
			print(f'  per-suite report files: {counts}')
		recent = [m for m in mtimes if m > time.time() - 1800]
		if len(recent) >= 2:
			pace = (recent[-1] - recent[0]) / (len(recent) - 1)
			print(f'  pace (last 30 min): {pace:.0f}s/execution')
			if state_file.is_file():
				remaining = state['total_executions'] - state['completed_executions']
				eta = now + timedelta(seconds=remaining * pace)
				print(f'  full-campaign ETA at this pace: {eta:%a %H:%M}')

	log = log_path()
	if log.is_file():
		lines = [ln for ln in log.read_text().splitlines() if ln.strip()]
		print('\nrunner log tail:')
		for line in lines[-3:]:
			print(f'  {line}')


if __name__ == '__main__':
	main()
