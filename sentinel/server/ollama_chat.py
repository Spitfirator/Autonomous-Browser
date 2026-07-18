"""Sentinel's bounded non-thinking Ollama adapter for browser-use."""

from typing import TypeVar, overload

from browser_use.llm.exceptions import ModelProviderError
from browser_use.llm.messages import BaseMessage
from browser_use.llm.ollama.chat import ChatOllama
from browser_use.llm.ollama.serializer import OllamaMessageSerializer
from browser_use.llm.views import ChatInvokeCompletion
from pydantic import BaseModel

T = TypeVar('T', bound=BaseModel)


class SentinelChatOllama(ChatOllama):
	"""Use Ollama's native structured output while disabling hidden thinking."""

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
		try:
			response = await self.get_client().chat(
				model=self.model,
				messages=ollama_messages,
				format=output_format.model_json_schema() if output_format is not None else None,
				options=self.ollama_options,
				think=False,
			)
			completion = response.message.content or ''
			if output_format is None:
				return ChatInvokeCompletion(completion=completion, usage=None)
			return ChatInvokeCompletion(completion=output_format.model_validate_json(completion), usage=None)
		except Exception as exc:
			raise ModelProviderError(message=str(exc), model=self.name) from exc
