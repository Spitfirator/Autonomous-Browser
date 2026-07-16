"""Per-run audit traces: every event of a run persisted to data/traces/<run_id>/.

Layout:
    data/traces/<run_id>/
        events.jsonl   one line per SentinelEvent (screenshots externalized)
        steps/         step-NNN.png|jpg extracted from step events
        meta.json      task, policy snapshot at start, outcome, enforcement summary

Registered as an EventHub listener (hub.add_listener), so it sees exactly what
the side panel sees — the trace IS the audit log. A run opens lazily on the
first event carrying its run_id and closes on task_done / task_error.
"""

import base64
import json
import logging
import time
from pathlib import Path
from typing import Any, TextIO

from server.config import ConfigStore
from server.events import SentinelEvent, StepEvent, TaskDone, TaskError, TaskStarted

logger = logging.getLogger('sentinel.traces')


class _RunTrace:
	def __init__(self, directory: Path, run_id: str, policies: dict[str, Any]) -> None:
		self.dir = directory
		self.dir.mkdir(parents=True, exist_ok=True)
		(self.dir / 'steps').mkdir(exist_ok=True)
		self.file: TextIO = (self.dir / 'events.jsonl').open('a')
		self.meta: dict[str, Any] = {
			'run_id': run_id,
			'started_at': time.time(),
			'policies': policies,
			'status': 'running',
		}
		self.event_counts: dict[str, int] = {}

	def write_meta(self) -> None:
		self.meta['event_counts'] = self.event_counts
		(self.dir / 'meta.json').write_text(json.dumps(self.meta, indent=2, default=str))


class TraceStore:
	def __init__(self, traces_dir: Path, config_store: ConfigStore) -> None:
		self._dir = traces_dir
		self._config_store = config_store
		self._open: dict[str, _RunTrace] = {}

	def on_event(self, event: SentinelEvent) -> None:
		run_id = event.run_id
		if run_id is None:
			return
		trace = self._open.get(run_id)
		if trace is None:
			trace = self._open_run(run_id)

		payload = event.model_dump(mode='json')
		trace.event_counts[event.type] = trace.event_counts.get(event.type, 0) + 1

		if isinstance(event, StepEvent):
			audit = self._config_store.get().policies.audit
			payload['screenshot_b64'] = None
			if event.screenshot_b64 and audit.store_screenshots:
				payload['screenshot_file'] = self._save_screenshot(trace, event.step, event.screenshot_b64)
			if not audit.store_model_reasoning:
				payload['thinking'] = None
				payload['memory'] = None

		try:
			trace.file.write(json.dumps(payload, default=str) + '\n')
			trace.file.flush()
		except OSError as e:
			logger.warning(f'Trace write failed for run {run_id}: {e}')

		if isinstance(event, TaskStarted):
			trace.meta.update(task=event.task, model=event.model, provider=event.provider, max_steps=event.max_steps)
			trace.write_meta()
		elif isinstance(event, TaskDone):
			trace.meta.update(
				status='done' if event.success else 'finished',
				success=event.success,
				final_result=(event.final_result or '')[:2000],
				steps=event.steps,
				duration_s=event.duration_s,
				usage=event.usage,
				enforcement=event.enforcement,
				ended_at=time.time(),
			)
			self._close_run(run_id)
		elif isinstance(event, TaskError):
			trace.meta.update(status=event.kind, error=event.error, ended_at=time.time())
			self._close_run(run_id)

	def _open_run(self, run_id: str) -> _RunTrace:
		# One run at a time (AgentRunner invariant) — close anything stale first.
		for stale_id in list(self._open):
			logger.warning(f'Closing stale trace {stale_id} (no task_done/task_error seen)')
			self._open[stale_id].meta['status'] = 'interrupted'
			self._close_run(stale_id)
		policies = self._config_store.get().policies.model_dump(mode='json')
		trace = _RunTrace(self._dir / run_id, run_id, policies)
		self._open[run_id] = trace
		logger.info(f'Trace opened: {trace.dir}')
		return trace

	def _close_run(self, run_id: str) -> None:
		trace = self._open.pop(run_id, None)
		if trace is None:
			return
		trace.write_meta()
		try:
			trace.file.close()
		except OSError:
			pass
		logger.info(f'Trace closed: {trace.dir} ({sum(trace.event_counts.values())} events)')

	def _save_screenshot(self, trace: _RunTrace, step: int, b64: str) -> str | None:
		try:
			raw = base64.b64decode(b64)
		except Exception:
			return None
		ext = 'png' if raw[:4] == b'\x89PNG' else 'jpg'
		name = f'steps/step-{step:03d}.{ext}'
		try:
			(trace.dir / name).write_bytes(raw)
			return name
		except OSError as e:
			logger.warning(f'Screenshot write failed: {e}')
			return None

	def close_all(self) -> None:
		for run_id in list(self._open):
			self._open[run_id].meta['status'] = 'interrupted'
			self._close_run(run_id)
