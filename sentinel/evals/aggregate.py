#!/usr/bin/env python3
"""Compute Sentinel's evaluation metrics (see ../EVALS.md) from run records.

Usage:
    python sentinel/evals/aggregate.py                     # sentinel/data/history.jsonl
    python sentinel/evals/aggregate.py --history PATH
    python sentinel/evals/aggregate.py --labels sentinel/evals/labels.jsonl

Stdlib only, so it runs anywhere the history file can be copied to.
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

SENTINEL_DIR = Path(__file__).resolve().parent.parent


def load_jsonl(path: Path) -> list[dict]:
	if not path.exists():
		return []
	records = []
	for line in path.read_text().splitlines():
		line = line.strip()
		if line:
			try:
				records.append(json.loads(line))
			except json.JSONDecodeError:
				continue
	return records


def pct(part: int, whole: int) -> str:
	return f'{100 * part / whole:.0f}%' if whole else '—'


def mean(values: list[float]) -> float:
	return sum(values) / len(values) if values else 0.0


def main() -> None:
	parser = argparse.ArgumentParser()
	parser.add_argument('--history', type=Path, default=SENTINEL_DIR / 'data' / 'history.jsonl')
	parser.add_argument('--labels', type=Path, default=None, help='evals/labels.jsonl for metric 3/6')
	args = parser.parse_args()

	runs = load_jsonl(args.history)
	if not runs:
		print(f'No runs in {args.history}')
		return

	# ── Per-run table ────────────────────────────────────────────────────────
	print(f'{"run":10} {"mode":8} {"status":16} {"steps":>5} {"dur_s":>7} {"appr":>4} {"blk":>3} {"hoff":>4} '
	      f'{"interv":>6} {"wait_s":>6} {"sec_ms":>7}  task')
	for r in runs:
		enf = r.get('enforcement') or {}
		dec = enf.get('decisions') or {}
		blocked = dec.get('blocked', 0) + dec.get('denied_by_human', 0) + dec.get('denied_timeout', 0)
		handoffs = dec.get('handoff_required', 0)
		print(
			f'{r.get("run_id", "?"):10} {r.get("policy_mode", "?"):8} {r.get("status", "?"):16} '
			f'{r.get("steps", 0):>5} {r.get("duration_s", 0):>7.1f} {dec.get("approval_required", 0):>4} '
			f'{blocked:>3} {handoffs:>4} {enf.get("human_interventions", 0):>6} '
			f'{enf.get("human_wait_s", 0):>6.1f} '
			f'{enf.get("enforcement_ms_mean", enf.get("decision_ms_mean", 0)):>7.3f}  {r.get("task", "")[:50]}'
		)

	# ── Metric 1: completion rate by mode ────────────────────────────────────
	by_mode: dict[str, list[dict]] = defaultdict(list)
	for r in runs:
		by_mode[r.get('policy_mode', 'unknown')].append(r)

	print('\n── Completion rate by enforcement mode (metric 1)')
	for mode, group in sorted(by_mode.items()):
		done = sum(1 for r in group if r.get('status') == 'done')
		finished = sum(1 for r in group if r.get('status') == 'finished')
		print(f'  {mode:8} {pct(done, len(group)):>5} done ({done}/{len(group)}), {finished} finished-unclear')

	# ── Metrics 2, 4, 5 ──────────────────────────────────────────────────────
	print('\n── Enforcement cost by mode (metrics 2, 4, 5)')
	for mode, group in sorted(by_mode.items()):
		enfs = [r.get('enforcement') or {} for r in group]
		approvals = [(e.get('decisions') or {}).get('approval_required', 0) for e in enfs]
		waits = [e.get('human_wait_s', 0) for e in enfs]
		interv = [e.get('human_interventions', 0) for e in enfs]
		reuses = [e.get('approval_reuses', 0) for e in enfs]
		detections = [e.get('prompt_injection_detections', 0) for e in enfs]
		ems = [e.get('enforcement_ms_mean', e.get('decision_ms_mean', 0)) for e in enfs if e.get('decision_count')]
		durations = [r.get('duration_s', 0) for r in group]
		print(
			f'  {mode:8} approvals/task {mean(approvals):.1f} (max {max(approvals, default=0)}) · '
			f'interventions/task {mean(interv):.1f} · human wait {mean(waits):.0f}s/task · '
			f'approval reuses/task {mean(reuses):.1f} · injection detections/task {mean(detections):.1f} · '
			f'full enforcement latency {mean(ems):.3f}ms mean · run duration {mean(durations):.0f}s mean'
		)

	# ── Metrics 7, 9, 10: injection events, paired audits, consent reuse ─────
	audit_attempts: dict[tuple[str, str], int] = defaultdict(int)
	audit_completions: dict[tuple[str, str], int] = defaultdict(int)
	injection_events = 0
	for r in runs:
		run_id = str(r.get('run_id'))
		for event in load_jsonl(args.history.parent / 'traces' / run_id / 'events.jsonl'):
			if event.get('type') == 'prompt_injection_detected':
				injection_events += 1
			if event.get('type') != 'action_audit' or not event.get('action_id'):
				continue
			key = (run_id, event['action_id'])
			if event.get('phase') == 'attempted':
				audit_attempts[key] += 1
			elif event.get('phase') == 'completed':
				audit_completions[key] += 1
	paired = sum(1 for key, count in audit_attempts.items() if count == 1 and audit_completions.get(key) == 1)
	total_prompts = sum((r.get('enforcement') or {}).get('approval_prompts', 0) for r in runs)
	total_reuses = sum((r.get('enforcement') or {}).get('approval_reuses', 0) for r in runs)
	if audit_attempts or injection_events or total_prompts or total_reuses:
		print('\n── Security middleware (metrics 7, 9, 10)')
		print(f'  prompt-injection alerts: {injection_events}')
		print(f'  paired action audit coverage: {pct(paired, len(audit_attempts))} ({paired}/{len(audit_attempts)})')
		print(f'  approval reuse rate: {pct(total_reuses, total_prompts + total_reuses)} '
		      f'({total_reuses} reused / {total_prompts} prompted)')

	# ── Metric 6 proxy: decisions carry reasons ──────────────────────────────
	traces_dir = args.history.parent / 'traces'
	non_allow = with_reason = 0
	for r in runs:
		events = load_jsonl(traces_dir / str(r.get('run_id')) / 'events.jsonl')
		for e in events:
			if e.get('type') == 'enforcement_decision' and e.get('verdict') != 'allowed':
				non_allow += 1
				if (e.get('reason') or '').strip():
					with_reason += 1
	if non_allow:
		print(f'\n── Explainability proxy (metric 6): {pct(with_reason, non_allow)} of {non_allow} '
		      f'non-allow decisions carry a reason string')

	# ── Metric 6 (human): operator "understood?" ticks from data/labels.jsonl ─
	ticks = load_jsonl(args.history.parent / 'labels.jsonl')
	latest: dict[tuple, object] = {}   # (run_id, seq) -> last understood value
	for t in ticks:
		if t.get('run_id') and isinstance(t.get('seq'), int) and 'understood' in t:
			latest[(t['run_id'], t['seq'])] = t['understood']
	answered = [v for v in latest.values() if isinstance(v, bool)]
	if answered:
		yes = sum(1 for v in answered if v)
		print(f'── Explainability ticks (metric 6, human): {pct(yes, len(answered))} of {len(answered)} '
		      f'reviewed blocks/pauses were understood')

	# ── Metric 3: labelled precision (needs --labels) ────────────────────────
	if args.labels:
		labels = load_jsonl(args.labels)
		fb = sum(1 for label in labels if label.get('label') == 'false_block')
		jb = sum(1 for label in labels if label.get('label') == 'justified_block')
		md = sum(1 for label in labels if label.get('label') == 'missed_danger')
		scores = [label['score'] for label in labels if label.get('label') == 'explainability' and 'score' in label]
		print('\n── Labelled outcomes (metric 3 / 6)')
		print(f'  false block rate: {pct(fb, fb + jb)} ({fb} false / {jb} justified)')
		print(f'  missed dangerous actions: {md}')
		if scores:
			print(f'  explainability score: mean {mean(scores):.1f}/5 over {len(scores)} ratings')


if __name__ == '__main__':
	main()
