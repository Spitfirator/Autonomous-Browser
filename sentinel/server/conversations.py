"""Chat conversations at data/conversations.jsonl.

Append-only, two record shapes discriminated by the presence of `role`:
  created: {"conversation_id", "title", "created_at"}
  turn:    {"conversation_id", "role": "user"|"agent", "text", "ts",
            "run_id": str|null, "kind": "task"|"followup"|"steer"|"result"|"error"}

A conversation is the ordering + run_id links between turns; the full audit
trail of each run stays in data/traces/<run_id>/. Titles left at the default
are derived at read time from the first user turn.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

logger = logging.getLogger('sentinel.conversations')

DEFAULT_TITLE = 'New chat'
_TITLE_CHARS = 60
_TURN_TEXT_CAP = 4000


class ConversationStore:
	def __init__(self, path: Path) -> None:
		self._path = path
		self._path.parent.mkdir(parents=True, exist_ok=True)

	def _append(self, record: dict[str, Any]) -> None:
		try:
			with self._path.open('a') as f:
				f.write(json.dumps(record, default=str) + '\n')
		except OSError as e:
			logger.warning(f'Failed to append conversation record: {e}')

	def _read_all(self) -> list[dict[str, Any]]:
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
			logger.warning(f'Failed to read conversations: {e}')
		return records

	@staticmethod
	def _derive_title(title: str, turns: list[dict[str, Any]]) -> str:
		if title != DEFAULT_TITLE:
			return title
		for turn in turns:
			if turn.get('role') == 'user' and turn.get('text'):
				text = ' '.join(str(turn['text']).split())
				return text[:_TITLE_CHARS] + ('…' if len(text) > _TITLE_CHARS else '')
		return title

	def create(self, title: str | None = None) -> dict[str, Any]:
		record = {
			'conversation_id': uuid4().hex[:8],
			'title': (title or '').strip() or DEFAULT_TITLE,
			'created_at': time.time(),
		}
		self._append(record)
		return record

	def append_turn(
		self,
		conversation_id: str,
		role: str,
		text: str,
		run_id: str | None = None,
		kind: str = 'task',
	) -> None:
		self._append({
			'conversation_id': conversation_id,
			'role': role,
			'text': (text or '')[:_TURN_TEXT_CAP],
			'ts': time.time(),
			'run_id': run_id,
			'kind': kind,
		})

	def exists(self, conversation_id: str) -> bool:
		return any(
			r.get('conversation_id') == conversation_id and 'role' not in r
			for r in self._read_all()
		)

	def get(self, conversation_id: str) -> dict[str, Any] | None:
		created: dict[str, Any] | None = None
		turns: list[dict[str, Any]] = []
		for r in self._read_all():
			if r.get('conversation_id') != conversation_id:
				continue
			if 'role' in r:
				turns.append(r)
			else:
				created = r
		if created is None:
			return None
		return {
			'conversation_id': conversation_id,
			'title': self._derive_title(created.get('title') or DEFAULT_TITLE, turns),
			'created_at': created.get('created_at'),
			'updated_at': turns[-1]['ts'] if turns else created.get('created_at'),
			'turns': turns,
		}

	def list(self) -> list[dict[str, Any]]:
		"""All conversations, most recently updated first."""
		created: dict[str, dict[str, Any]] = {}
		turns_by_id: dict[str, list[dict[str, Any]]] = {}
		for r in self._read_all():
			cid = r.get('conversation_id')
			if not cid:
				continue
			if 'role' in r:
				turns_by_id.setdefault(cid, []).append(r)
			else:
				created[cid] = r
		out: list[dict[str, Any]] = []
		for cid, rec in created.items():
			turns = turns_by_id.get(cid, [])
			preview = next((t['text'] for t in reversed(turns) if t.get('text')), '')
			out.append({
				'conversation_id': cid,
				'title': self._derive_title(rec.get('title') or DEFAULT_TITLE, turns),
				'created_at': rec.get('created_at'),
				'updated_at': turns[-1]['ts'] if turns else rec.get('created_at'),
				'turn_count': len(turns),
				'preview': str(preview)[:120],
			})
		out.sort(key=lambda c: c['updated_at'] or 0, reverse=True)
		return out
