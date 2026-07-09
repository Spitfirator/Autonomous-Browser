"""Operator explainability labels at data/labels.jsonl.

One line per tick: {"run_id", "seq", "understood": bool|null, "ts"}. Append-only;
the last write for a given (run_id, seq) wins on read. `understood: null` clears
a prior tick. Feeds EVALS.md metric 6 (can the operator tell why an action was
blocked or paused) — aggregate.py reads this file for the human measure.
"""

import json
import logging
import time
from pathlib import Path

logger = logging.getLogger('sentinel.labels')


class LabelStore:
	def __init__(self, path: Path) -> None:
		self._path = path
		self._path.parent.mkdir(parents=True, exist_ok=True)

	def set_understood(self, run_id: str, seq: int, understood: bool | None) -> None:
		record = {'run_id': run_id, 'seq': seq, 'understood': understood, 'ts': time.time()}
		try:
			with self._path.open('a') as f:
				f.write(json.dumps(record) + '\n')
		except OSError as e:
			logger.warning(f'Failed to append label: {e}')

	def for_run(self, run_id: str) -> dict[int, bool | None]:
		"""seq -> understood (True/False/None), last write wins."""
		if not self._path.exists():
			return {}
		out: dict[int, bool | None] = {}
		try:
			for line in self._path.read_text().splitlines():
				line = line.strip()
				if not line:
					continue
				try:
					rec = json.loads(line)
				except json.JSONDecodeError:
					continue
				if rec.get('run_id') == run_id and isinstance(rec.get('seq'), int) and 'understood' in rec:
					out[rec['seq']] = rec['understood']
		except OSError as e:
			logger.warning(f'Failed to read labels: {e}')
		return out
