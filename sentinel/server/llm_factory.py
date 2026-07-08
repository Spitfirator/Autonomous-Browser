"""Builds governed BaseChatModel instances from dashboard config.

Wrap order: GovernedLLM(ThrottledLLM(Chat*)) — see governance/__init__.py.
"""

import logging
import os
from collections.abc import Callable

from browser_use.llm.base import BaseChatModel

from server.config import ModelConfig
from server.events import SentinelEvent
from server.governance import GovernedLLM, RunContext, ThrottledLLM

logger = logging.getLogger('sentinel.llm')

# provider -> (import, env var candidates in priority order)
_PROVIDERS: dict[str, tuple[str, list[str]]] = {
	'gemini': ('ChatGoogle', ['GEMINI_API_KEY', 'GOOGLE_API_KEY']),
	'groq': ('ChatGroq', ['GROQ_API_KEY']),
	'openai': ('ChatOpenAI', ['OPENAI_API_KEY']),
	'anthropic': ('ChatAnthropic', ['ANTHROPIC_API_KEY']),
	'openrouter': ('ChatOpenRouter', ['OPENROUTER_API_KEY']),
}


class MissingApiKeyError(Exception):
	pass


def resolve_api_key(provider: str) -> str | None:
	for env_name in _PROVIDERS[provider][1]:
		value = os.environ.get(env_name)
		if value:
			return value
	return None


def build_chat(cfg: ModelConfig) -> BaseChatModel:
	"""Instantiate the raw provider chat model (no wrappers)."""
	class_name, env_names = _PROVIDERS[cfg.provider]
	api_key = resolve_api_key(cfg.provider)
	if not api_key:
		raise MissingApiKeyError(
			f"No API key for provider '{cfg.provider}'. Set {' or '.join(env_names)} "
			f'in browser-use/.env (or via the dashboard Models tab).'
		)

	import browser_use.llm as llm_module

	chat_class = getattr(llm_module, class_name)
	kwargs: dict = {'model': cfg.model, 'api_key': api_key}
	if cfg.temperature is not None:
		kwargs['temperature'] = cfg.temperature
	return chat_class(**kwargs)


def build_governed_llm(
	cfg: ModelConfig,
	emit: Callable[[SentinelEvent], None],
	ctx: RunContext,
	is_fallback: bool = False,
) -> GovernedLLM:
	chat: BaseChatModel = build_chat(cfg)
	if cfg.throttle is not None:
		chat = ThrottledLLM(
			chat,
			min_interval_s=cfg.throttle.min_interval_s,
			backoff_s=cfg.throttle.backoff_s,
			max_retries=cfg.throttle.max_retries,
		)
	return GovernedLLM(chat, emit, ctx, is_fallback=is_fallback)


def build_llm_pair(
	cfg: ModelConfig,
	emit: Callable[[SentinelEvent], None],
	ctx: RunContext,
) -> tuple[GovernedLLM, GovernedLLM | None]:
	"""Primary + optional fallback (both governed so events/budgets survive a switch)."""
	primary = build_governed_llm(cfg, emit, ctx)
	fallback: GovernedLLM | None = None
	if cfg.fallback is not None:
		try:
			fallback = build_governed_llm(cfg.fallback, emit, ctx, is_fallback=True)
		except MissingApiKeyError as e:
			logger.warning(f'Fallback model unavailable, continuing without it: {e}')
	return primary, fallback
