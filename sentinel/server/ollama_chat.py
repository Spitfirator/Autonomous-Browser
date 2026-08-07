"""Sentinel's bounded Ollama adapter for browser-use.

Ollama exposes native model reasoning separately from the final response.  The
reasoning channel is deliberately neither returned to BrowserUse nor persisted;
only the final message may satisfy the requested Pydantic action schema.
"""

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, TypeVar, overload

from browser_use.llm.exceptions import ModelProviderError
from browser_use.llm.messages import BaseMessage
from browser_use.llm.ollama.chat import ChatOllama
from browser_use.llm.ollama.serializer import OllamaMessageSerializer
from browser_use.llm.views import ChatInvokeCompletion, ChatInvokeUsage
from pydantic import BaseModel, ValidationError

T = TypeVar('T', bound=BaseModel)


@dataclass
class SentinelChatOllama(ChatOllama):
	"""Use Ollama structured output without exposing native reasoning.

	``native_thinking`` is explicit so historical non-thinking configurations
	remain loadable.  The final replicated Qwen 3.5 profile sets it to ``True``.
	Diagnostics contain counts and categories only, never prompts, completions or
	the model's reasoning text.
	"""

	native_thinking: bool = False
	_requests: int = field(default=0, init=False, repr=False)
	_structured_requests: int = field(default=0, init=False, repr=False)
	_successes: int = field(default=0, init=False, repr=False)
	_structured_successes: int = field(default=0, init=False, repr=False)
	_native_thinking_responses: int = field(default=0, init=False, repr=False)
	_prompt_tokens: int = field(default=0, init=False, repr=False)
	_completion_tokens: int = field(default=0, init=False, repr=False)
	_max_prompt_tokens: int = field(default=0, init=False, repr=False)
	_max_completion_tokens: int = field(default=0, init=False, repr=False)
	_stop_reasons: Counter[str] = field(default_factory=Counter, init=False, repr=False)
	_failures: Counter[str] = field(default_factory=Counter, init=False, repr=False)

	def diagnostics_snapshot(self) -> dict[str, Any]:
		"""Return privacy-safe reliability evidence for the current task."""

		return {
			'requests': self._requests,
			'structured_requests': self._structured_requests,
			'successes': self._successes,
			'structured_successes': self._structured_successes,
			'native_thinking_responses': self._native_thinking_responses,
			'prompt_tokens': self._prompt_tokens,
			'completion_tokens': self._completion_tokens,
			'max_prompt_tokens': self._max_prompt_tokens,
			'max_completion_tokens': self._max_completion_tokens,
			'stop_reasons': dict(sorted(self._stop_reasons.items())),
			'failure_categories': dict(sorted(self._failures.items())),
		}

	@staticmethod
	def _usage(response: Any) -> ChatInvokeUsage | None:
		prompt_tokens = getattr(response, 'prompt_eval_count', None)
		completion_tokens = getattr(response, 'eval_count', None)
		if not isinstance(prompt_tokens, int) or not isinstance(completion_tokens, int):
			return None
		return ChatInvokeUsage(
			prompt_tokens=prompt_tokens,
			prompt_cached_tokens=None,
			prompt_cache_creation_tokens=None,
			prompt_image_tokens=None,
			completion_tokens=completion_tokens,
			total_tokens=prompt_tokens + completion_tokens,
		)

	@staticmethod
	def _provider_category(exc: Exception) -> str:
		text = str(exc).lower()
		if 'connect' in text or 'connection' in text:
			return 'connection'
		if 'timeout' in text or 'timed out' in text:
			return 'timeout'
		return type(exc).__name__.lower()

	def _fail(self, category: str) -> None:
		self._failures[category] += 1
		raise ModelProviderError(message=f'structured_output:{category}', model=self.name)

	@overload
	async def ainvoke(
		self, messages: list[BaseMessage], output_format: None = None, **kwargs: object
	) -> ChatInvokeCompletion[str]: ...

	@overload
	async def ainvoke(
		self, messages: list[BaseMessage], output_format: type[T], **kwargs: object
	) -> ChatInvokeCompletion[T]: ...

	async def ainvoke(
		self,
		messages: list[BaseMessage],
		output_format: type[T] | None = None,
		**kwargs: object,
	) -> ChatInvokeCompletion[T] | ChatInvokeCompletion[str]:
		ollama_messages = OllamaMessageSerializer.serialize_messages(messages)
		self._requests += 1
		if output_format is not None:
			self._structured_requests += 1
		try:
			response = await self.get_client().chat(
				model=self.model,
				messages=ollama_messages,
				format=output_format.model_json_schema() if output_format is not None else None,
				options=self.ollama_options,
				think=self.native_thinking,
				stream=False,
			)
		except ModelProviderError:
			raise
		except Exception as exc:
			category = f'provider_{self._provider_category(exc)}'
			self._failures[category] += 1
			raise ModelProviderError(message=category, model=self.name) from exc

		message = response.message
		completion = message.content or ''
		thinking = getattr(message, 'thinking', None)
		if isinstance(thinking, str) and thinking.strip():
			self._native_thinking_responses += 1
		stop_reason = getattr(response, 'done_reason', None)
		if isinstance(stop_reason, str) and stop_reason:
			self._stop_reasons[stop_reason] += 1
		usage = self._usage(response)
		if usage is not None:
			self._prompt_tokens += usage.prompt_tokens
			self._completion_tokens += usage.completion_tokens
			self._max_prompt_tokens = max(self._max_prompt_tokens, usage.prompt_tokens)
			self._max_completion_tokens = max(self._max_completion_tokens, usage.completion_tokens)

		if output_format is None:
			self._successes += 1
			return ChatInvokeCompletion(
				completion=completion,
				thinking=None,
				usage=usage,
				stop_reason=stop_reason,
			)

		if stop_reason == 'length':
			self._fail('output_truncated')
		stripped = completion.strip()
		if not stripped:
			self._fail('empty_content')
		if '```' in stripped:
			self._fail('markdown_fence')
		if '<think' in stripped.lower() or '</think>' in stripped.lower():
			self._fail('reasoning_leak')
		try:
			validated = output_format.model_validate_json(stripped)
		except ValidationError as exc:
			error_types = {str(error.get('type', '')) for error in exc.errors()}
			category = 'invalid_json' if 'json_invalid' in error_types else 'schema_validation'
			self._fail(category)

		self._successes += 1
		self._structured_successes += 1
		return ChatInvokeCompletion(
			completion=validated,
			thinking=None,
			usage=usage,
			stop_reason=stop_reason,
		)
