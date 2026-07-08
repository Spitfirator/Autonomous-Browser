"""PolicyEngine v0: the single decision point for action enforcement.

Reads policies live from the ConfigStore, so dashboard edits apply to the very
next action. Extend `evaluate` (or replace it with a rule pipeline) when the
full enforcement engine lands.
"""

import logging
from typing import Literal

from browser_use.utils import match_url_with_domain_pattern
from pydantic import BaseModel

from server.config import ConfigStore

logger = logging.getLogger('sentinel.policy')

# Actions that don't operate on a page/URL — domain policies don't apply.
NON_PAGE_ACTIONS = {'done', 'wait', 'search', 'write_file', 'replace_file', 'read_file', 'request_human_control'}


class PolicyDecision(BaseModel):
	verdict: Literal['allow', 'block', 'approve']
	rule: str
	reason: str


def _matches(url: str, pattern: str) -> bool:
	"""match_url_with_domain_pattern treats schemeless patterns as https-only;
	for policy lists 'example.com' should mean the domain on any scheme."""
	if '://' in pattern:
		return match_url_with_domain_pattern(url, pattern)
	return match_url_with_domain_pattern(url, f'http*://{pattern}')


class PolicyEngine:
	def __init__(self, config_store: ConfigStore) -> None:
		self._config_store = config_store

	def evaluate(self, action_name: str, params: dict, current_url: str | None) -> PolicyDecision:
		policies = self._config_store.get().policies

		# 1. Hard-blocked action types (also excluded from the LLM schema at run
		#    start; this live check covers policy edits made mid-run).
		if action_name in policies.blocked_actions:
			return PolicyDecision(
				verdict='block',
				rule='blocked_action',
				reason=f"action '{action_name}' is in the blocked actions list",
			)

		# 2. Domain policies against the target URL (navigate) or current page.
		target_url = None
		if action_name not in NON_PAGE_ACTIONS:
			if action_name == 'navigate' and isinstance(params.get('url'), str):
				target_url = params['url']
			else:
				target_url = current_url
		if target_url:
			for pattern in policies.domain_blocklist:
				if _matches(target_url, pattern):
					return PolicyDecision(
						verdict='block',
						rule='domain_blocklist',
						reason=f"'{target_url}' matches blocklisted domain '{pattern}'",
					)
			if policies.domain_allowlist is not None and not any(
				_matches(target_url, pattern) for pattern in policies.domain_allowlist
			):
				return PolicyDecision(
					verdict='block',
					rule='domain_allowlist',
					reason=f"'{target_url}' is not on the domain allowlist",
				)

		# 3. Human-in-the-loop gate.
		if action_name in policies.approval_required_actions:
			return PolicyDecision(
				verdict='approve',
				rule='approval_required',
				reason=f"action '{action_name}' requires human approval",
			)

		return PolicyDecision(verdict='allow', rule='default', reason='no policy matched')
