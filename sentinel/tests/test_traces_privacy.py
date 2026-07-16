import json
from pathlib import Path

from server.config import ConfigStore
from server.events import StepEvent, TaskDone, TaskStarted
from server.traces import TraceStore

PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB'


def _write_run(store: TraceStore, run_id: str) -> None:
	store.on_event(TaskStarted(run_id=run_id, task='test', max_steps=1, model='dummy', provider='test'))
	store.on_event(
		StepEvent(
			run_id=run_id,
			step=1,
			url='https://example.test',
			title='Example',
			thinking='private chain of thought',
			memory='private page memory',
			screenshot_b64=PNG_B64,
		)
	)
	store.on_event(TaskDone(run_id=run_id, success=True, steps=1, duration_s=0.1))


def _step_payload(path: Path) -> dict:
	events = [json.loads(line) for line in path.read_text().splitlines()]
	return next(event for event in events if event['type'] == 'step')


def test_sensitive_visual_and_reasoning_retention_is_off_by_default(tmp_path: Path) -> None:
	config = ConfigStore(tmp_path / 'config.json')
	traces = TraceStore(tmp_path / 'traces', config)
	_write_run(traces, 'safe-default')
	payload = _step_payload(tmp_path / 'traces' / 'safe-default' / 'events.jsonl')
	assert payload['screenshot_b64'] is None
	assert 'screenshot_file' not in payload
	assert payload['thinking'] is None
	assert payload['memory'] is None
	assert list((tmp_path / 'traces' / 'safe-default' / 'steps').iterdir()) == []


def test_operator_can_explicitly_enable_sensitive_trace_retention(tmp_path: Path) -> None:
	config = ConfigStore(tmp_path / 'config.json')
	config.update({'policies': {'audit': {'store_screenshots': True, 'store_model_reasoning': True}}})
	traces = TraceStore(tmp_path / 'traces', config)
	_write_run(traces, 'opted-in')
	payload = _step_payload(tmp_path / 'traces' / 'opted-in' / 'events.jsonl')
	assert payload['screenshot_b64'] is None
	assert payload['screenshot_file'] == 'steps/step-001.png'
	assert payload['thinking'] == 'private chain of thought'
	assert payload['memory'] == 'private page memory'
	assert (tmp_path / 'traces' / 'opted-in' / 'steps' / 'step-001.png').exists()
