"""Sentinel configuration: pydantic models + JSON-persisted ConfigStore."""

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

logger = logging.getLogger('sentinel.config')

# ── Paths ────────────────────────────────────────────────────────────────────
SENTINEL_DIR = Path(__file__).resolve().parent.parent          # .../sentinel
WORKSPACE_DIR = SENTINEL_DIR.parent                            # .../Autonomous Browser
BROWSER_USE_DIR = WORKSPACE_DIR / 'browser-use'
ENV_FILE = BROWSER_USE_DIR / '.env'
DATA_DIR = SENTINEL_DIR / 'data'
CONFIG_FILE = DATA_DIR / 'config.json'
HISTORY_FILE = DATA_DIR / 'history.jsonl'
BROWSER_STATE_FILE = DATA_DIR / 'browser.json'
# The 'browser-use-user-data-dir-' marker substring is load-bearing: it stops
# BrowserProfile._copy_profile() from copying this profile into a throwaway
# temp dir, which would destroy persistence (browser_use/browser/profile.py:844).
PROFILE_DIR = DATA_DIR / 'profile' / 'browser-use-user-data-dir-sentinel'
EXTENSION_DIST = SENTINEL_DIR / 'extension' / 'dist'

HOST = '127.0.0.1'
PORT = int(os.environ.get('SENTINEL_PORT', '8765'))
BASE_URL = f'http://{HOST}:{PORT}'

# Env var names the dashboard is allowed to read (presence only) and write.
KNOWN_API_KEYS = [
	'GEMINI_API_KEY',
	'GOOGLE_API_KEY',
	'GROQ_API_KEY',
	'OPENAI_API_KEY',
	'ANTHROPIC_API_KEY',
	'OPENROUTER_API_KEY',
]

Provider = Literal['ollama', 'gemini', 'groq', 'openai', 'anthropic', 'openrouter']

# enforce: decisions are applied. shadow: everything is allowed but would-be
# verdicts are still evaluated + logged (for measuring false blocks / missed
# dangerous actions). off: policy evaluation is skipped entirely (baseline for
# measuring enforcement overhead and completion-rate deltas).
PolicyMode = Literal['enforce', 'shadow', 'off']

# Action names registered by browser-use v0.13.2 Tools (for dashboard checklists).
KNOWN_ACTIONS = [
	'search', 'navigate', 'go_back', 'wait', 'click', 'input', 'upload_file',
	'switch', 'close', 'extract', 'search_page', 'find_elements', 'scroll',
	'send_keys', 'find_text', 'screenshot', 'save_as_pdf', 'dropdown_options',
	'select_dropdown', 'write_file', 'replace_file', 'read_file', 'evaluate', 'done',
	'request_human_control',   # Sentinel's own action (governance/governed_tools.py)
]


# ── Models ───────────────────────────────────────────────────────────────────
class ThrottleConfig(BaseModel):
	"""Client-side pacing to stay under free-tier rate limits (from run_agent.py)."""

	model_config = ConfigDict(extra='forbid')

	min_interval_s: float = 5.0    # Gemini free tier ~15 RPM -> 1 per 4s; 5s for safety
	backoff_s: float = 30.0        # under browser-use's 75s LLM timeout so retries survive
	max_retries: int = 2


class ModelConfig(BaseModel):
	model_config = ConfigDict(extra='forbid')

	provider: Provider = 'ollama'
	model: str = 'qwen3.5-agentdojo:4b'
	temperature: float | None = None
	throttle: ThrottleConfig | None = None
	fallback: 'ModelConfig | None' = None


def default_model_config() -> ModelConfig:
	return ModelConfig(
		provider='ollama',
		model='qwen3.5-agentdojo:4b',
		temperature=0.7,
		throttle=None,
		fallback=ModelConfig(
			provider='gemini',
			model='gemini-3.1-flash-lite',
			throttle=ThrottleConfig(),
			fallback=None,
		)
	)


class Budgets(BaseModel):
	model_config = ConfigDict(extra='forbid')

	max_steps: int = 30
	max_llm_calls: int = 60
	approval_timeout_s: float = 120.0
	handover_timeout_s: float = 900.0   # how long the agent waits for a human takeover


class PromptInjectionPolicy(BaseModel):
	"""Indirect prompt-injection detection at the untrusted page boundary."""

	model_config = ConfigDict(extra='forbid')

	enabled: bool = True
	detection_threshold: float = Field(default=0.55, ge=0.0, le=1.0)
	# At/above this confidence, protected sinks influenced by the page are
	# blocked instead of merely held for approval.
	block_threshold: float = Field(default=0.85, ge=0.0, le=1.0)

	@model_validator(mode='after')
	def thresholds_are_ordered(self) -> 'PromptInjectionPolicy':
		if self.block_threshold < self.detection_threshold:
			raise ValueError('block_threshold must be greater than or equal to detection_threshold')
		return self


class DataFlowPolicy(BaseModel):
	"""Rules for data moving from sensitive/untrusted sources into sinks."""

	model_config = ConfigDict(extra='forbid')

	enabled: bool = True
	# Sensitive values may only be disclosed to these explicitly trusted
	# destinations.  Empty by default: logins and payments should use handoff.
	trusted_domains: list[str] = Field(default_factory=list)
	sensitive_data_verdict: Literal['block', 'approve'] = 'block'


class AdaptiveApprovalPolicy(BaseModel):
	"""Risk-adaptive approval and bounded consent reuse to reduce fatigue."""

	model_config = ConfigDict(extra='forbid')

	enabled: bool = True
	approval_risk_threshold: int = Field(default=55, ge=0, le=100)
	grant_ttl_s: float = Field(default=300.0, ge=1.0, le=3600.0)
	grant_max_uses: int = Field(default=3, ge=1, le=100)
	max_prompts_per_run: int = Field(default=4, ge=1, le=100)
	# Once the prompt budget is exhausted, one browser handoff is less prone to
	# rubber-stamping than a stream of near-identical approval cards.
	fatigue_strategy: Literal['handoff', 'block'] = 'handoff'


class AuditPolicy(BaseModel):
	"""At-rest trace retention; live side-panel monitoring is unaffected."""

	model_config = ConfigDict(extra='forbid')

	# Screenshots and free-form model reasoning can contain page/private data
	# that deterministic text redaction cannot reliably remove.
	store_screenshots: bool = False
	store_model_reasoning: bool = False


class Policies(BaseModel):
	model_config = ConfigDict(extra='forbid')

	mode: PolicyMode = 'enforce'
	domain_allowlist: list[str] | None = None   # None = allow all; glob syntax e.g. "*.google.com"
	domain_blocklist: list[str] = Field(default_factory=list)
	blocked_actions: list[str] = Field(default_factory=list)
	approval_required_actions: list[str] = Field(default_factory=lambda: ['upload_file'])
	# Any page action on a matching domain pauses for approval in the side panel.
	approval_required_domains: list[str] = Field(default_factory=list)
	# First touch of a matching domain forces a handoff to the human (login,
	# payment, account pages). After the human hands control back once, the agent
	# may act there for the rest of the run — the human vouched for the context.
	sensitive_domains: list[str] = Field(default_factory=list)
	prompt_injection: PromptInjectionPolicy = Field(default_factory=PromptInjectionPolicy)
	data_flow: DataFlowPolicy = Field(default_factory=DataFlowPolicy)
	adaptive_approvals: AdaptiveApprovalPolicy = Field(default_factory=AdaptiveApprovalPolicy)
	audit: AuditPolicy = Field(default_factory=AuditPolicy)
	budgets: Budgets = Field(default_factory=Budgets)


class SentinelConfig(BaseModel):
	model_config = ConfigDict(extra='forbid')

	model: ModelConfig = Field(default_factory=default_model_config)
	policies: Policies = Field(default_factory=Policies)
	use_judge: bool = False          # judge = 1 extra LLM call per task; off to save free-tier quota
	pinned_extension_id: str | None = None


# ── Store ────────────────────────────────────────────────────────────────────
def _deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
	"""Recursively merge patch into base. Lists and scalars are replaced, dicts merged."""
	out = dict(base)
	for key, value in patch.items():
		if isinstance(value, dict) and isinstance(out.get(key), dict):
			out[key] = _deep_merge(out[key], value)
		else:
			out[key] = value
	return out


class ConfigStore:
	"""Loads/persists SentinelConfig at data/config.json with atomic writes."""

	def __init__(self, path: Path = CONFIG_FILE) -> None:
		self._path = path
		self._config = self._load()

	def _load(self) -> SentinelConfig:
		if self._path.exists():
			try:
				return SentinelConfig.model_validate(json.loads(self._path.read_text()))
			except Exception as e:
				logger.warning(f'Invalid config at {self._path}, falling back to defaults: {e}')
		config = SentinelConfig()
		self._save(config)
		return config

	def _save(self, config: SentinelConfig) -> None:
		self._path.parent.mkdir(parents=True, exist_ok=True)
		fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix='.config-')
		try:
			with os.fdopen(fd, 'w') as f:
				f.write(config.model_dump_json(indent=2))
			os.replace(tmp, self._path)
		except BaseException:
			Path(tmp).unlink(missing_ok=True)
			raise

	def get(self) -> SentinelConfig:
		return self._config

	def update(self, patch: dict[str, Any]) -> SentinelConfig:
		"""Apply a partial patch, validate the merged result, persist, and return it."""
		merged = _deep_merge(self._config.model_dump(mode='json'), patch)
		config = SentinelConfig.model_validate(merged)   # raises ValidationError on bad input
		self._config = config
		self._save(config)
		return config
