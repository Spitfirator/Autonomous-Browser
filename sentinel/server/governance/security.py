"""Security analysis primitives for Sentinel's enforcement middleware.

This module deliberately contains no model calls.  It provides deterministic,
auditable signals that can be used in benchmarks and combined with the model-
level instruction boundary in :mod:`governed_llm`:

* isolate the untrusted browser/read-state regions of an agent prompt;
* detect common indirect prompt-injection techniques without logging payloads;
* classify action capabilities and sensitive values;
* propagate page taint into a per-action risk assessment; and
* produce redacted audit/approval payloads.

The detector is defense in depth, not an oracle.  Unknown page content remains
labelled ``untrusted_web`` even when no signature matches, so downstream policy
does not equate "not detected" with "trusted".
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
from collections.abc import Iterable
from pathlib import PurePath
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import BaseModel, Field

from server.config import AdaptiveApprovalPolicy, DataFlowPolicy, PromptInjectionPolicy

Severity = Literal['low', 'medium', 'high', 'critical']
Recommendation = Literal['allow', 'approve', 'block']


class PromptInjectionFinding(BaseModel):
	"""Privacy-preserving result of scanning one page-state prompt region."""

	detected: bool = False
	score: float = Field(default=0.0, ge=0.0, le=1.0)
	severity: Severity = 'low'
	signals: list[str] = Field(default_factory=list)
	content_hash: str = ''
	url: str | None = None


class RiskAssessment(BaseModel):
	"""Normalized security context attached to every attempted action."""

	score: int = Field(default=0, ge=0, le=100)
	recommendation: Recommendation = 'allow'
	rule: str = 'risk_below_threshold'
	reason: str = 'no elevated security risk detected'
	factors: list[str] = Field(default_factory=list)
	capabilities: list[str] = Field(default_factory=list)
	taint_labels: list[str] = Field(default_factory=list)
	sensitive_categories: list[str] = Field(default_factory=list)
	target_origin: str | None = None
	enforcement_ms: float = 0.0
	params_digest: str
	approval_key: str
	redacted_params: dict[str, Any] = Field(default_factory=dict)


# Weighted signatures are intentionally phrased as behavior, not benchmark-
# specific payloads. Ambiguous phrases need multiple independent signals;
# unambiguous authority-confusion markers (explicit instruction override or a
# forged role header) may cross the threshold alone.
_INJECTION_SIGNATURES: tuple[tuple[str, re.Pattern[str], float], ...] = (
	(
		'override_instructions',
		re.compile(
			r'\b(?:ignore|disregard|forget|override)\b.{0,80}\b(?:all\s+)?(?:previous|prior|above|system|developer|user)\b.{0,40}\b(?:instructions?|i\w{0,2}nstructions?|messages?|prompt|rules?)\b',
			re.I | re.S,
		),
		0.90,
	),
	(
		'forged_role_marker',
		re.compile(
			r'(?:^|\n)\s*(?:#{2,}\s*)?\(?\s*(?:system|developer|assistant)[ _-](?:message|instruction)\s*\)?\s*:?',
			re.I | re.M,
		),
		0.90,
	),
	(
		'authority_impersonation',
		re.compile(r'\b(?:system|developer|administrator|security)\s*(?:message|notice|instruction|override)\b', re.I),
		0.25,
	),
	(
		'role_reassignment',
		re.compile(r'\b(?:you are now|act as|new role|switch roles?|your (?:new|real) (?:task|goal|objective))\b', re.I),
		0.28,
	),
	(
		'secrecy_or_evasion',
		re.compile(r'\b(?:do not|don[\'’]t|never)\b.{0,50}\b(?:tell|show|mention|reveal|alert|ask)\b|\b(?:secretly|silently|without (?:the )?user(?:\s+knowing)?)\b', re.I | re.S),
		0.24,
	),
	(
		'exfiltration_request',
		re.compile(r'\b(?:send|upload|post|forward|copy|leak|exfiltrat\w*)\b.{0,100}\b(?:passwords?|credentials?|api[ _-]?keys?|tokens?|cookies?|secrets?|private|history|files?|data)\b', re.I | re.S),
		0.38,
	),
	(
		'sensitive_data_request',
		re.compile(r'\b(?:passwords?|credentials?|api[ _-]?keys?|access tokens?|session cookies?|private keys?|seed phrases?)\b', re.I),
		0.17,
	),
	(
		'prompt_or_tool_markup',
		re.compile(r'<\/?(?:system|developer|assistant|tool|function(?:_call)?|instructions?)\b|\[(?:system|developer|assistant|tool)\s*(?:message)?\]', re.I),
		0.35,
	),
	(
		'jailbreak_language',
		re.compile(r'\b(?:jailbreak|prompt injection|bypass (?:the )?(?:policy|guardrails?|safety)|DAN mode)\b', re.I),
		0.25,
	),
	(
		'encoded_instruction',
		re.compile(r'\b(?:decode|base64|rot13)\b.{0,80}\b(?:instruction|command|payload|execute|follow)\b', re.I | re.S),
		0.22,
	),
	(
		'task_substitution',
		re.compile(
			r'\b(?:before\s+you\s+can\s+(?:solve|complete|continue)|before\s+(?:solving|completing|continuing))\b.{0,140}\b(?:do|follow|complete|perform)\b.{0,40}\b(?:following|this)\b.{0,30}\b(?:first|instruction|task|step)',
			re.I | re.S,
		),
		0.68,
	),
	(
		'strict_instruction_adoption',
		re.compile(r'\b(?:strictly|must)\s+(?:adhere to|follow|obey|execute)\b.{0,70}\b(?:following|instruction|command|task)\b', re.I | re.S),
		0.58,
	),
	(
		'untrusted_task_marker',
		re.compile(r'(?:^|\n)\s*(?:TODO|ACTION REQUIRED|NEW TASK)\s*[:\-]', re.I | re.M),
		0.55,
	),
	(
		'consequential_directive',
		re.compile(
			r'(?:^|[.!?]\s+|:\s*)(?:please\s+)?(?:send|email|forward|delete|remove|create|invite|add|reserve|book|transfer|change|update|modify|post|publish|upload|visit|open|get|collect|concatenate|say|tell|make)\b',
			re.I,
		),
		0.32,
	),
	(
		'tool_use_directive',
		re.compile(r'\b(?:you\s+should|you\s+must|must|first|then|finally)\s+(?:use|call|invoke)\s+(?:the\s+)?(?:tool|function)\b', re.I),
		0.58,
	),
	(
		'untrusted_model_address',
		re.compile(
			r'\b(?:important\s+)?message\s+from\s+.{1,80}\s+to\s+you\s*,?\s*(?:the\s+)?(?:AI|assistant|agent|language model|model\s+developed\s+by)',
			re.I | re.S,
		),
		0.65,
	),
	(
		'behavioral_directive',
		re.compile(
			r'\byou\s+(?:should|must|need\s+to|have\s+to)\s+(?:immediately\s+)?(?:stop|reply|send|open|visit|click|use|call|invoke|ignore|go|say|tell|delete|transfer|upload|post|create)\b',
			re.I,
		),
		0.25,
	),
)

_REGION_RE = re.compile(r'<(browser_state|read_state)>\s*(.*?)\s*</\1>', re.I | re.S)
_CURRENT_TAB_RE = re.compile(r'Current tab:\s*([A-Za-z0-9_-]+)', re.I)
_TAB_RE = re.compile(r'^Tab\s+([A-Za-z0-9_-]+):\s*(\S+)', re.I | re.M)
_RESERVED_BOUNDARY_RE = re.compile(
	r'<\/?(?:user_request|agent_history|agent_state|browser_state|read_state|page_specific_actions|step_info|system|developer|assistant|tool)(?:\s[^>]*)?>',
	re.I,
)
_STRUCTURED_INSTRUCTION_BLOCK_RE = re.compile(
	r'<(?P<tag>information|instructions?|system|developer|assistant|tool|message|notice|task|command)\b[^>]*>'
	r'(?P<body>.*?)</(?P=tag)\s*>',
	re.I | re.S,
)
_REMOVED_UNTRUSTED_INSTRUCTION = '[SENTINEL REMOVED UNTRUSTED INSTRUCTION-LIKE CONTENT]'


def extract_untrusted_regions(messages: Iterable[Any]) -> tuple[str, str | None]:
	"""Return the latest browser/read-state text and its best-effort current URL.

	The state message is generated by browser-use and may contain attacker text
	that resembles our closing tag.  Using all matches from the final user
	message and finding the current tab separately is safer than trusting a
	page-provided delimiter as an authority boundary.
	"""

	latest = ''
	for message in messages:
		if getattr(message, 'role', None) != 'user':
			continue
		text = getattr(message, 'text', '')
		if '<browser_state>' in text:
			latest = text
	if not latest:
		return '', None

	regions = [match.group(2) for match in _REGION_RE.finditer(latest)]
	# If an injected closing tag confused the non-greedy matcher, still retain
	# everything from the first opening browser boundary to the last closing one.
	start = latest.find('<browser_state>')
	end = latest.rfind('</browser_state>')
	if start >= 0 and end > start:
		regions.append(latest[start + len('<browser_state>') : end])
	untrusted = '\n'.join(regions)

	current_url: str | None = None
	current_match = _CURRENT_TAB_RE.search(latest)
	if current_match:
		tab_id = current_match.group(1)
		for candidate_id, url in _TAB_RE.findall(latest):
			if candidate_id == tab_id:
				current_url = url
				break
	return untrusted, current_url


def neutralize_untrusted_boundaries(messages: list[Any]) -> list[Any]:
	"""Escape forged authority/state tags inside untrusted prompt regions.

	Normal DOM tags remain untouched because the agent needs them for element
	semantics. Only tags reserved by the model protocol are neutralized, while
	the genuine outer ``browser_state``/``read_state`` delimiters are retained.
	"""

	out = list(messages)
	for index in range(len(out) - 1, -1, -1):
		message = out[index]
		if getattr(message, 'role', None) != 'user' or '<browser_state>' not in getattr(message, 'text', ''):
			continue
		copied = message.model_copy(deep=True)
		if isinstance(copied.content, str):
			copied.content = _neutralize_state_text(copied.content)
		elif isinstance(copied.content, list):
			for part in copied.content:
				if getattr(part, 'type', None) == 'text':
					part.text = _neutralize_state_text(part.text)
		out[index] = copied
		break
	return out


def _neutralize_state_text(text: str) -> str:
	start = text.find('<browser_state>')
	end = text.rfind('</browser_state>')
	if start < 0 or end <= start:
		return text
	open_end = start + len('<browser_state>')
	inner = _RESERVED_BOUNDARY_RE.sub(lambda match: html.escape(match.group(0)), text[open_end:end])
	after = text[end + len('</browser_state>') :]

	read_start = after.find('<read_state>')
	read_end = after.rfind('</read_state>')
	if read_start >= 0 and read_end > read_start:
		read_open_end = read_start + len('<read_state>')
		read_inner = _RESERVED_BOUNDARY_RE.sub(
			lambda match: html.escape(match.group(0)), after[read_open_end:read_end]
		)
		after = (
			after[:read_open_end]
			+ read_inner
			+ after[read_end:]
		)
	return text[:open_end] + inner + '</browser_state>' + after


_DETECTION_ESCAPE_NOISE_RE = re.compile(r'\\+[ \t]*')
_DETECTION_WHITESPACE_RE = re.compile(r'\s+')


def _normalize_for_detection(text: str) -> str:
	"""Strip serialization noise that splits injected phrases mid-sentence.

	When an untrusted payload is embedded in a returned document (a CSV cell, a
	YAML/JSON string), the serializer wraps long lines with backslash + newline +
	indentation continuations — e.g. ``"do the\\\n    \\ following first"``. Those
	escape+wrap runs break the contiguous phrases the signature regexes match, so
	an injection that scores 1.0 on its own drops below threshold once embedded.
	Collapsing backslash-escape runs and whitespace to single spaces restores the
	original phrasing for scoring only; the raw text is still what gets hashed,
	sanitized, and shown.
	"""

	return _DETECTION_WHITESPACE_RE.sub(' ', _DETECTION_ESCAPE_NOISE_RE.sub(' ', text))


def detect_prompt_injection(
	text: str,
	policy: PromptInjectionPolicy,
	url: str | None = None,
) -> PromptInjectionFinding:
	"""Score instruction-like content using independent, explainable signals."""

	if not policy.enabled or not text:
		return PromptInjectionFinding(content_hash=_content_hash(text), url=url)

	# Scan the raw text and an escape-normalized copy, taking the union of
	# signals. Normalization only ever reveals phrases the wrapping hid, so a
	# score can rise but never fall relative to scanning the raw text alone.
	normalized = _normalize_for_detection(text)
	variants = (text, normalized) if normalized != text else (text,)

	signals: list[str] = []
	score = 0.0
	for name, pattern, weight in _INJECTION_SIGNATURES:
		if any(pattern.search(variant) for variant in variants):
			signals.append(name)
			score += weight

	# Imperative language addressed to the agent is a weak signal on its own,
	# but meaningfully strengthens authority/secret/exfiltration combinations.
	directive_re = re.compile(
		r'\b(?:assistant|agent|AI|browser)\s*[:,]\s*(?:you must|must|do|open|click|send|ignore)\b', re.I
	)
	if any(directive_re.search(variant) for variant in variants):
		signals.append('agent_directive')
		score += 0.18

	score = min(round(score, 3), 1.0)
	detected = score >= policy.detection_threshold
	if score >= policy.block_threshold:
		severity: Severity = 'critical'
	elif score >= max(policy.detection_threshold, 0.72):
		severity = 'high'
	elif detected:
		severity = 'medium'
	else:
		severity = 'low'
	return PromptInjectionFinding(
		detected=detected,
		score=score,
		severity=severity,
		signals=signals,
		content_hash=_content_hash(text),
		url=url,
	)


def sanitize_detected_untrusted_text(
	text: str,
	policy: PromptInjectionPolicy,
	url: str | None = None,
) -> str:
	"""Redact detected instruction blocks while retaining adjacent facts.

	If no safe structural separation is available, redact the whole value. This
	uses only content structure and detector output—never task IDs, expected
	answers, benchmark oracles, or payload-specific values.
	"""

	changed = False

	def replace(match: re.Match[str]) -> str:
		nonlocal changed
		if not detect_prompt_injection(match.group('body'), policy, url).detected:
			return match.group(0)
		changed = True
		return _REMOVED_UNTRUSTED_INSTRUCTION

	redacted = _STRUCTURED_INSTRUCTION_BLOCK_RE.sub(replace, text)
	return redacted if changed else _REMOVED_UNTRUSTED_INSTRUCTION


def url_origin(url: str | None) -> str | None:
	if not url:
		return None
	parsed = urlparse(url)
	if not parsed.scheme or not parsed.hostname:
		return None
	try:
		port = f':{parsed.port}' if parsed.port else ''
	except ValueError:
		return None
	return f'{parsed.scheme.lower()}://{parsed.hostname.lower()}{port}'


_CAPABILITIES: dict[str, tuple[str, ...]] = {
	'navigate': ('network_read', 'navigation'),
	'search': ('network_read', 'network_write', 'data_disclosure'),
	'go_back': ('navigation',),
	'click': ('page_write',),
	'input': ('page_write', 'data_disclosure'),
	'send_keys': ('page_write', 'data_disclosure'),
	'select_dropdown': ('page_write',),
	'upload_file': ('local_file_read', 'data_disclosure', 'page_write'),
	'evaluate': ('code_execution', 'page_write'),
	'write_file': ('local_file_write',),
	'replace_file': ('local_file_write',),
	'save_as_pdf': ('local_file_write',),
	'done': ('task_completion',),
	'close': ('navigation',),
	'switch': ('navigation',),
}

_BASE_RISK: dict[str, int] = {
	'navigate': 10,
	'search': 20,
	'go_back': 5,
	'click': 20,
	'input': 30,
	'send_keys': 30,
	'select_dropdown': 20,
	'upload_file': 65,
	'evaluate': 75,
	'write_file': 45,
	'replace_file': 50,
	'save_as_pdf': 25,
	'close': 10,
	'switch': 5,
}

_EXTERNAL_EFFECTS = {'search', 'navigate', 'click', 'input', 'send_keys', 'select_dropdown', 'upload_file', 'evaluate'}
_INJECTION_HARD_BLOCK_SINKS = {
	'search',
	'navigate',
	'input',
	'send_keys',
	'upload_file',
	'evaluate',
	'write_file',
	'replace_file',
	'done',
	'request_human_control',
}
_APPROVAL_ELIGIBLE = _EXTERNAL_EFFECTS | {'write_file', 'replace_file', 'save_as_pdf', 'close'}

_SENSITIVE_KEY_RE = re.compile(
	r'(?:pass(?:word|wd)?|pin|cvv|cvc|card(?:_?number)?|api[_-]?key|secret|token|cookie|authorization|private[_-]?key|seed[_-]?phrase|ssn)',
	re.I,
)
_SENSITIVE_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
	('secret_placeholder', re.compile(r'<secret>[^<]{1,200}</secret>', re.I)),
	('private_key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
	('api_key', re.compile(r'\b(?:sk|pk|rk|gh[opusr]|xox[baprs])[-_][A-Za-z0-9_-]{12,}\b')),
	('aws_key', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
	('jwt', re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b')),
)
_CARD_CANDIDATE_RE = re.compile(r'(?<!\d)(?:\d[ -]*?){13,19}(?!\d)')
_SENSITIVE_ASSIGNMENT_RE = re.compile(
	r'\b(password|passwd|passcode|api[ _-]?key|access[ _-]?token|secret|authorization|cookie|cvv|cvc|card[ _-]?number)\b\s*(?:is|:|=)\s*["\']?\S{4,}',
	re.I,
)
_SENSITIVE_TARGET_RE = re.compile(
	r'\b(?:pass(?:word|code|phrase)?|one[ -]?time|otp|2fa|verification code|cvv|cvc|card number|api[ _-]?key|access token|secret|private key|seed phrase|ssn)\b',
	re.I,
)
_HIGH_IMPACT_TARGET_RE = re.compile(
	r'\b(?:buy now|place order|confirm (?:purchase|payment|transfer)|pay now|send (?:message|email|money)|publish|post now|delete|remove (?:account|user|member)|transfer|book now|reserve(?: hotel)?|subscribe|invite (?:user|member)|add (?:user|member)|update (?:scheduled )?(?:transaction|payment)|change password)\b',
	re.I,
)


def sensitive_categories(value: Any, parent_key: str = '') -> set[str]:
	"""Find credential/payment/private-data categories without retaining values."""

	found: set[str] = set()
	if isinstance(value, dict):
		for key, child in value.items():
			key_text = str(key)
			if _SENSITIVE_KEY_RE.search(key_text) and child not in (None, '', False):
				found.add(_category_for_key(key_text))
			found.update(sensitive_categories(child, key_text))
	elif isinstance(value, (list, tuple, set)):
		for child in value:
			found.update(sensitive_categories(child, parent_key))
	elif isinstance(value, str):
		for category, pattern in _SENSITIVE_VALUE_PATTERNS:
			if pattern.search(value):
				found.add(category)
		if any(_luhn_valid(match.group(0)) for match in _CARD_CANDIDATE_RE.finditer(value)):
			found.add('payment_card')
		assignment = _SENSITIVE_ASSIGNMENT_RE.search(value)
		if assignment:
			found.add(_category_for_key(assignment.group(1)))
		if value.startswith(('http://', 'https://')):
			try:
				parsed = urlparse(value)
				if parsed.username or parsed.password:
					found.add('credential')
				url_fields = [*parse_qsl(parsed.query, keep_blank_values=True)]
				if '=' in parsed.fragment:
					url_fields.extend(parse_qsl(parsed.fragment, keep_blank_values=True))
				for query_key, query_value in url_fields:
					if _SENSITIVE_KEY_RE.search(query_key) and query_value:
						found.add(_category_for_key(query_key))
			except Exception:
				pass
		if _SENSITIVE_KEY_RE.search(parent_key) and value:
			found.add(_category_for_key(parent_key))
	return found


def redact_params(params: dict[str, Any], action_name: str | None = None) -> dict[str, Any]:
	"""Return a JSON-safe copy suitable for events and approval UI."""

	def redact(value: Any, parent_key: str = '') -> Any:
		if value is None or isinstance(value, (bool, int, float)):
			return value
		if isinstance(value, dict):
			return {str(key): redact(child, str(key)) for key, child in value.items()}
		if isinstance(value, (list, tuple, set)):
			return [redact(child, parent_key) for child in value]
		if not isinstance(value, str):
			return str(value)
		if 'url' in parent_key.lower() or value.startswith(('http://', 'https://')):
			return redact_url(value)
		categories = sensitive_categories(value, parent_key)
		if categories:
			return f'[REDACTED:{"+".join(sorted(categories))}]'
		if action_name == 'upload_file' and ('path' in parent_key.lower() or PurePath(value).is_absolute()):
			return '[LOCAL_FILE]'
		return value if len(value) <= 500 else value[:497] + '...'

	return redact(params)


def redact_text(text: str | None) -> str | None:
	"""Redact a free-text event/history field when it contains a known secret."""

	if text is None:
		return None
	return str(redact_params({'text': text}).get('text', ''))


def assess_action(
	action_name: str,
	params: dict[str, Any],
	current_url: str | None,
	prompt_finding: PromptInjectionFinding | None,
	prompt_policy: PromptInjectionPolicy,
	data_flow: DataFlowPolicy,
	adaptive: AdaptiveApprovalPolicy,
	origin_is_trusted: bool,
	digest_key: bytes,
	target_context: dict[str, str] | None = None,
) -> RiskAssessment:
	"""Propagate source taint to action sinks and make a deterministic recommendation."""

	capabilities = list(_CAPABILITIES.get(action_name, ('read_only',)))
	score = _BASE_RISK.get(action_name, 0)
	factors: list[str] = []
	taints = ['untrusted_web'] if current_url and url_origin(current_url) else []
	categories_set = sensitive_categories(params)
	target_categories = _target_sensitive_categories(target_context or {}) if action_name == 'input' else set()
	categories_set.update(target_categories)
	categories = sorted(categories_set)
	if categories:
		taints.extend(f'sensitive:{category}' for category in categories)
		factors.append(f'sensitive data in action parameters ({", ".join(categories)})')
		score += 60

	if action_name == 'navigate' and isinstance(params.get('url'), str):
		target_url = params['url']
	elif action_name == 'search':
		target_url = None  # the configured search provider is outside the current origin
	else:
		target_url = current_url
	target_origin = url_origin(target_url)
	current_origin = url_origin(current_url)
	cross_origin = bool(current_origin and target_origin and current_origin != target_origin)

	active_injection = bool(prompt_policy.enabled and prompt_finding and prompt_finding.detected)
	if active_injection and prompt_finding is not None:
		taints.append('prompt_injection_suspected')
		factors.append(f'page prompt-injection score {prompt_finding.score:.2f}')
		score += 55 if prompt_finding.score >= 0.85 else 35
		if action_name in _EXTERNAL_EFFECTS:
			factors.append('action can create an external side effect')
	if cross_origin and active_injection:
		factors.append('tainted workflow crosses an origin boundary')
		score += 20
	if action_name == 'navigate' and active_injection and isinstance(params.get('url'), str) and urlparse(params['url']).query:
		factors.append('tainted navigation carries query data')
		score += 15
	if 'local_file_read' in capabilities:
		taints.append('local_file')
		factors.append('action reads a local file into web content')
		score += 20
	if action_name == 'click' and _is_high_impact_target(target_context or {}):
		factors.append('target element appears to trigger a consequential external action')
		score += 35

	score = min(score, 100)
	redacted = redact_params(params, action_name)
	if target_categories and isinstance(redacted, dict):
		# InputTextAction uses the generic key "text"; DOM metadata is what tells
		# us the destination is a password/payment/OTP field.
		for key in ('text', 'value'):
			if key in redacted and redacted[key] not in ('', None):
				redacted[key] = f'[REDACTED:{"+".join(sorted(target_categories))}]'
	digest = _params_digest(params, digest_key)
	target_fingerprint = None
	if target_context:
		target_fingerprint = hmac.new(
			digest_key,
			json.dumps(target_context, sort_keys=True, separators=(',', ':')).encode(),
			hashlib.sha256,
		).hexdigest()[:24]
	navigation_path = None
	if action_name == 'navigate' and isinstance(params.get('url'), str):
		navigation_path = urlparse(params['url']).path or '/'
	strict_params_digest = digest if action_name in {'upload_file', 'evaluate', 'write_file', 'replace_file'} else None
	scope_material = json.dumps(
		{
			'action': action_name,
			'origin': target_origin,
			'capabilities': capabilities,
			'taints': sorted(set(taints)),
			'categories': categories,
			'target_fingerprint': target_fingerprint,
			'navigation_path': navigation_path,
			'strict_params_digest': strict_params_digest,
		},
		sort_keys=True,
		separators=(',', ':'),
	).encode()
	approval_key = hmac.new(digest_key, scope_material, hashlib.sha256).hexdigest()[:24]

	recommendation: Recommendation = 'allow'
	rule = 'risk_below_threshold'
	reason = 'no elevated security risk detected'

	high_confidence_injection_sink = action_name in _INJECTION_HARD_BLOCK_SINKS or (
		action_name == 'click' and _is_high_impact_target(target_context or {})
	)
	if (
		active_injection
		and prompt_finding is not None
		and prompt_finding.score >= prompt_policy.block_threshold
		and high_confidence_injection_sink
	):
		recommendation = 'block'
		rule = 'prompt_injection_data_flow'
		reason = (
			f'high-confidence prompt injection ({prompt_finding.score:.2f}) is influencing a protected {action_name} sink'
		)
	elif data_flow.enabled and categories and not origin_is_trusted:
		recommendation = data_flow.sensitive_data_verdict
		rule = 'sensitive_data_flow'
		reason = (
			f"{action_name} would disclose {', '.join(categories)} to an origin that is not trusted for sensitive data"
		)
	elif adaptive.enabled and action_name in _APPROVAL_ELIGIBLE and score >= adaptive.approval_risk_threshold:
		recommendation = 'approve'
		rule = 'adaptive_risk'
		reason = f'{action_name} has risk score {score}/100: ' + '; '.join(factors or ['high-impact action'])

	return RiskAssessment(
		score=score,
		recommendation=recommendation,
		rule=rule,
		reason=reason,
		factors=factors,
		capabilities=capabilities,
		taint_labels=sorted(set(taints)),
		sensitive_categories=categories,
		target_origin=target_origin,
		params_digest=digest,
		approval_key=approval_key,
		redacted_params=redacted,
	)


def _category_for_key(key: str) -> str:
	key = key.lower()
	if any(part in key for part in ('card', 'cvv', 'cvc')):
		return 'payment_data'
	if 'private' in key or 'seed' in key:
		return 'private_key'
	if 'ssn' in key:
		return 'government_id'
	if any(part in key for part in ('token', 'api', 'secret', 'cookie', 'authorization')):
		return 'access_token'
	return 'credential'


def _target_sensitive_categories(context: dict[str, str]) -> set[str]:
	joined = ' '.join(str(value) for value in context.values())
	autocomplete = context.get('autocomplete', '').lower()
	input_type = context.get('type', '').lower()
	if input_type == 'password' or autocomplete in ('current-password', 'new-password'):
		return {'credential'}
	if autocomplete == 'one-time-code':
		return {'one_time_code'}
	if autocomplete.startswith('cc-'):
		return {'payment_data'}
	match = _SENSITIVE_TARGET_RE.search(joined)
	if not match:
		return set()
	return {_category_for_key(match.group(0))}


def _is_high_impact_target(context: dict[str, str]) -> bool:
	return bool(_HIGH_IMPACT_TARGET_RE.search(' '.join(str(value) for value in context.values())))


def _luhn_valid(candidate: str) -> bool:
	digits = [int(char) for char in candidate if char.isdigit()]
	if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
		return False
	checksum = 0
	parity = len(digits) % 2
	for index, digit in enumerate(digits):
		if index % 2 == parity:
			digit *= 2
			if digit > 9:
				digit -= 9
		checksum += digit
	return checksum % 10 == 0


def _content_hash(text: str) -> str:
	return hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()[:16] if text else ''


def _params_digest(params: dict[str, Any], key: bytes) -> str:
	try:
		payload = json.dumps(params, sort_keys=True, separators=(',', ':'), default=str).encode()
	except Exception:
		payload = repr(params).encode()
	return hmac.new(key, payload, hashlib.sha256).hexdigest()[:24]


def redact_url(url: str) -> str:
	"""Strip credentials and sensitive query values from a URL for telemetry."""
	try:
		parsed = urlparse(url)
		if not parsed.scheme:
			return url
		query = []
		for key, value in parse_qsl(parsed.query, keep_blank_values=True):
			if _SENSITIVE_KEY_RE.search(key) or sensitive_categories(value, key):
				value = '[REDACTED]'
			query.append((key, value))
		fragment = parsed.fragment
		if '=' in fragment:
			fragment_fields = []
			for key, value in parse_qsl(fragment, keep_blank_values=True):
				if _SENSITIVE_KEY_RE.search(key) or sensitive_categories(value, key):
					value = '[REDACTED]'
				fragment_fields.append((key, value))
			fragment = urlencode(fragment_fields)
		elif sensitive_categories(fragment):
			fragment = '[REDACTED]'
		netloc = parsed.hostname or ''
		if parsed.port:
			netloc += f':{parsed.port}'
		return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, urlencode(query), fragment))
	except Exception:
		return '[INVALID_URL]'
