"""ThrottledLLM: provider-agnostic client-side rate limiting.

Generalizes run_agent.py's ThrottledChatGoogle from a ChatGoogle subclass into a
delegation wrapper so it composes with any BaseChatModel (Gemini, Groq, ...).
Paces requests to min_interval_s and waits out 429 cooldowns instead of dying.
"""

import asyncio
import logging
import time
from typing import Any

from browser_use.llm.base import BaseChatModel
from browser_use.llm.exceptions import ModelRateLimitError

logger = logging.getLogger('sentinel.throttle')


class ThrottledLLM:
	"""Plain mutable class on purpose: browser-use's TokenCost monkeypatches
	`ainvoke` on the instance and the Agent setattr's `_verified_api_keys`."""

	def __init__(
		self,
		inner: BaseChatModel,
		min_interval_s: float = 5.0,
		backoff_s: float = 30.0,
		max_retries: int = 2,
	) -> None:
		self._inner = inner
		self.min_interval_s = min_interval_s
		self.backoff_s = backoff_s
		self.max_retries = max_retries
		self._last_call = 0.0
		self._pace_lock = asyncio.Lock()

	# BaseChatModel protocol surface -----------------------------------------
	@property
	def model(self) -> str:
		return self._inner.model

	@property
	def provider(self) -> str:
		return self._inner.provider

	@property
	def name(self) -> str:
		return self._inner.name

	def __getattr__(self, item: str) -> Any:
		# Delegate anything else (model_name, etc.) to the wrapped model.
		return getattr(self._inner, item)

	async def ainvoke(self, messages: list[Any], output_format: type | None = None, **kwargs: Any) -> Any:
		for attempt in range(self.max_retries + 1):
			async with self._pace_lock:
				wait = self._last_call + self.min_interval_s - time.monotonic()
				if wait > 0:
					await asyncio.sleep(wait)
				self._last_call = time.monotonic()
			try:
				return await self._inner.ainvoke(messages, output_format, **kwargs)
			except ModelRateLimitError:
				if attempt < self.max_retries:
					logger.info(f'[throttle] {self.model} rate limited — backing off {self.backoff_s:.0f}s (retry {attempt + 1}/{self.max_retries})')
					await asyncio.sleep(self.backoff_s)
					continue
				raise   # let the Agent's native fallback_llm switch take over
			except Exception as e:
				msg = str(e)
				if ('429' in msg or 'RESOURCE_EXHAUSTED' in msg) and attempt < self.max_retries:
					logger.info(f'[throttle] {self.model} 429 — backing off {self.backoff_s:.0f}s (retry {attempt + 1}/{self.max_retries})')
					await asyncio.sleep(self.backoff_s)
					continue
				raise
		raise RuntimeError('unreachable')   # loop always returns or raises
