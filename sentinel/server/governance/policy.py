"""PolicyEngine: the single decision point for action enforcement.

Reads policies live from the ConfigStore, so dashboard edits apply to the very
next action. Rule order (first match wins):

  1. blocked_actions          -> block    (action type is forbidden outright)
  2. domain_blocklist         -> block    (target/current URL matches)
  3. domain_allowlist         -> block    (URL matches nothing on the list)
  4. dynamic injection/sensitive flow -> block or handoff
  5. sensitive_domains        -> handoff  (first touch of the domain this run;
                                           the human takes over in the browser)
  6. approval_required_actions/domains -> approve (side-panel consent gate)
  7. adaptive action risk     -> approve
  8. default                  -> allow

Modes (policies.mode): 'enforce' applies verdicts; 'shadow' evaluates rules 1-7
and reports the would-be verdict in PolicyDecision.shadow_verdict while
returning allow (log-only, for false-block/missed-danger evals); 'off' skips
evaluation entirely (overhead + completion-rate baseline).
"""

import logging
from fnmatch import fnmatch
from typing import Literal
from urllib.parse import urlparse

from browser_use.utils import match_url_with_domain_pattern
from pydantic import BaseModel

from server.config import ConfigStore, Policies, PolicyMode
from server.governance.security import RiskAssessment, redact_url

logger = logging.getLogger('sentinel.policy')

# Actions that don't operate on a page/URL — domain policies don't apply.
NON_PAGE_ACTIONS = {'done', 'wait', 'search', 'write_file', 'replace_file', 'read_file', 'request_human_control'}

Verdict = Literal['allow', 'block', 'approve', 'handoff']


class PolicyDecision(BaseModel):
	verdict: Verdict
	rule: str
	reason: str
	mode: PolicyMode = 'enforce'
	# The would-be verdict in shadow mode (verdict itself stays 'allow').
	shadow_verdict: Verdict | None = None
	# The domain pattern that matched, for rules that need follow-up state
	# (e.g. sensitive_domains marks the pattern as handed-over after the human
	# returns control).
	pattern: str | None = None
	# Opaque, per-run scope for an explicit "allow similar" approval grant.
	approval_key: str | None = None


def entry_matches(url: str, entry: str) -> bool:
	"""Does `url` match one Sentinel policy-list entry? Four entry shapes, from
	most rigid to most precise:

	  keyword    'facebook'          -> host CONTAINS the word: blocks facebook.com,
	                                     www.facebook.com, m.facebook.com, business.facebook.net…
	                                     (a bare word with no dot = maximum rigidity)
	  domain     'facebook.com'      -> that domain + all its subdomains, any scheme
	                                     (NOT lookalikes: notfacebook.com stays allowed)
	  glob       '*.facebook.com'    -> fnmatch on the host (apex included for *.x)
	  full URL   'https://facebook.com' -> scheme-aware match (browser-use semantics)

	Kept deliberately in sync with `to_watchdog_patterns` below so the LLM-level
	decision (this) and the browser navigation net (prohibited_domains) agree."""
	entry = entry.strip().lower()
	if not entry:
		return False
	if '://' in entry:
		return match_url_with_domain_pattern(url, entry)
	host = (urlparse(url).hostname or '').lower()
	if not host:
		return False
	if '*' in entry:
		if entry.startswith('*.'):
			parent = entry[2:]
			return host == parent or host.endswith(f'.{parent}') or fnmatch(host, entry)
		return fnmatch(host, entry)
	if '.' in entry:                       # domain: apex + subdomains
		return host == entry or host.endswith(f'.{entry}')
	return entry in host                   # keyword: substring anywhere in the host


def first_match(url: str, entries: list[str]) -> str | None:
	"""The first entry that matches, or None. Returns the entry so the caller can
	explain *why* (which rule fired)."""
	for entry in entries:
		if entry_matches(url, entry):
			return entry
	return None


def to_watchdog_patterns(entries: list[str]) -> list[str]:
	"""Translate Sentinel entries into browser-use allowed/prohibited_domains
	glob patterns that reproduce `entry_matches` at the navigation layer. Keep
	this and `entry_matches` in lockstep (tests/test_policy_matching.py)."""
	patterns: list[str] = []
	for entry in entries:
		e = entry.strip().lower()
		if not e:
			continue
		if '://' in e or '*' in e:
			patterns.append(e)                 # pass through (already a pattern/URL)
		elif '.' in e:
			patterns.append(f'*.{e}')          # domain -> apex + subdomains
		else:
			patterns.append(f'*{e}*')          # keyword -> host substring
	return patterns


class PolicyEngine:
	def __init__(self, config_store: ConfigStore) -> None:
		self._config_store = config_store

	@property
	def mode(self) -> PolicyMode:
		return self._config_store.get().policies.mode

	@property
	def policies(self) -> Policies:
		"""Live policy snapshot for risk analysis at the next action boundary."""
		return self._config_store.get().policies

	def evaluate(
		self,
		action_name: str,
		params: dict,
		current_url: str | None,
		handed_over_patterns: set[str] | None = None,
		risk: RiskAssessment | None = None,
	) -> PolicyDecision:
		"""handed_over_patterns: sensitive-domain patterns already cleared by a
		completed human handoff this run (tracked per-run in RunContext)."""
		policies = self._config_store.get().policies

		if policies.mode == 'off':
			return PolicyDecision(verdict='allow', rule='enforcement_off', reason='enforcement mode is off', mode='off')

		decision = self._evaluate_rules(action_name, params, current_url, handed_over_patterns or set(), policies, risk)
		if policies.mode == 'shadow' and decision.verdict != 'allow':
			return PolicyDecision(
				verdict='allow',
				rule=decision.rule,
				reason=f'[shadow] would {decision.verdict}: {decision.reason}',
				mode='shadow',
				shadow_verdict=decision.verdict,
				pattern=decision.pattern,
				approval_key=decision.approval_key,
			)
		decision.mode = policies.mode
		return decision

	def _evaluate_rules(
		self,
		action_name: str,
		params: dict,
		current_url: str | None,
		handed_over_patterns: set[str],
		policies,
		risk: RiskAssessment | None,
	) -> PolicyDecision:
		# 1. Hard-blocked action types (also excluded from the LLM schema at run
		#    start; this live check covers policy edits made mid-run).
		if action_name in policies.blocked_actions:
			return PolicyDecision(
				verdict='block',
				rule='blocked_action',
				reason=f"action '{action_name}' is in the blocked actions list",
			)

		# Domain rules apply to the target URL (navigate) or the current page.
		target_url = None
		if action_name not in NON_PAGE_ACTIONS:
			if action_name == 'navigate' and isinstance(params.get('url'), str):
				target_url = params['url']
			else:
				target_url = current_url

		if target_url:
			display_url = redact_url(target_url)
			# 2. Blocklist.
			blocked = first_match(target_url, policies.domain_blocklist)
			if blocked is not None:
				return PolicyDecision(
					verdict='block',
					rule='domain_blocklist',
					reason=f"'{display_url}' matches blocked entry '{blocked}'",
					pattern=blocked,
				)
			# 3. Allowlist (when enabled, anything not on it is blocked).
			if policies.domain_allowlist is not None and first_match(target_url, policies.domain_allowlist) is None:
				return PolicyDecision(
					verdict='block',
					rule='domain_allowlist',
					reason=f"'{display_url}' is not on the domain allowlist",
				)
		# 4. Dynamic data-flow and prompt-injection enforcement. Static hard
		# blocks and the allowlist above always win. Dynamic hard blocks and
		# human-only data handoffs must be classified before a generic sensitive-
		# domain handoff, so an injection-induced action cannot be reframed as an
		# ordinary operator step.
		if risk is not None and risk.recommendation == 'block':
			return PolicyDecision(
				verdict='block',
				rule=risk.rule,
				reason=risk.reason,
				approval_key=risk.approval_key,
			)
		if risk is not None and risk.recommendation == 'handoff':
			return PolicyDecision(
				verdict='handoff',
				rule=risk.rule,
				reason=risk.reason,
				approval_key=risk.approval_key,
			)

		# 5. Sensitive domains: force a human handoff on first touch this run.
		if target_url:
			sensitive = first_match(target_url, [p for p in policies.sensitive_domains if p not in handed_over_patterns])
			if sensitive is not None:
				return PolicyDecision(
					verdict='handoff',
					rule='sensitive_domain',
					reason=(
						f"'{redact_url(target_url)}' matches sensitive entry '{sensitive}' — "
						f'a human must take over in the browser for this step'
					),
					pattern=sensitive,
				)

		# 6. Human-in-the-loop approval gate (by action type or by domain).
		if action_name in policies.approval_required_actions:
			return PolicyDecision(
				verdict='approve',
				rule='approval_required_action',
				reason=f"action '{action_name}' requires human approval",
				approval_key=risk.approval_key if risk is not None else None,
			)
		if target_url:
			approval = first_match(target_url, policies.approval_required_domains)
			if approval is not None:
				return PolicyDecision(
					verdict='approve',
					rule='approval_required_domain',
					reason=f"'{redact_url(target_url)}' matches approval-required entry '{approval}'",
					pattern=approval,
					approval_key=risk.approval_key if risk is not None else None,
				)
		if risk is not None and risk.recommendation == 'approve':
			return PolicyDecision(
				verdict='approve',
				rule=risk.rule,
				reason=risk.reason,
				approval_key=risk.approval_key,
			)

		# 7. Default.
		return PolicyDecision(verdict='allow', rule='default', reason='no policy matched')
