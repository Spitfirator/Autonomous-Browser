"""Append-only run history at data/history.jsonl (no screenshots, small records)."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger('sentinel.history')


class HistoryStore:
	def __init__(self, path: Path) -> None:
		self._path = path
		self._path.parent.mkdir(parents=True, exist_ok=True)

	def append(self, record: dict[str, Any]) -> None:
		try:
			with self._path.open('a') as f:
				f.write(json.dumps(record, default=str) + '\n')
		except OSError as e:
			logger.warning(f'Failed to append history record: {e}')

	def list(self, limit: int = 50) -> list[dict[str, Any]]:
		"""Most recent first."""
		if not self._path.exists():
			return []
		records: list[dict[str, Any]] = []
		try:
			for line in self._path.read_text().splitlines():
				line = line.strip()
				if not line:
					continue
				try:
					records.append(json.loads(line))
				except json.JSONDecodeError:
					continue
		except OSError as e:
			logger.warning(f'Failed to read history: {e}')
		return list(reversed(records[-limit:]))
