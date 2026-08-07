from types import SimpleNamespace

import pytest
from browser_use.llm.exceptions import ModelProviderError
from pydantic import BaseModel

from server.ollama_chat import SentinelChatOllama


class ExampleOutput(BaseModel):
	action: str
	count: int


class FakeClient:
	def __init__(self, response: SimpleNamespace | None = None, error: Exception | None = None) -> None:
		self.response = response
		self.error = error
		self.calls: list[dict[str, object]] = []

	async def chat(self, **kwargs: object) -> SimpleNamespace:
		self.calls.append(kwargs)
		if self.error is not None:
			raise self.error
		assert self.response is not None
		return self.response


def _response(
	content: str,
	*,
	thinking: str = 'private reasoning',
	done_reason: str = 'stop',
) -> SimpleNamespace:
	return SimpleNamespace(
		message=SimpleNamespace(content=content, thinking=thinking),
		done_reason=done_reason,
		prompt_eval_count=11,
		eval_count=7,
	)


def _chat(client: FakeClient, *, native_thinking: bool = True) -> SentinelChatOllama:
	chat = SentinelChatOllama(model='qwen3.5-test', native_thinking=native_thinking)
	chat.get_client = lambda: client  # type: ignore[method-assign]
	return chat


@pytest.mark.asyncio
async def test_native_thinking_is_separate_from_validated_final_output() -> None:
	client = FakeClient(_response('{"action":"done","count":1}'))
	chat = _chat(client)

	result = await chat.ainvoke([], ExampleOutput)

	assert result.completion == ExampleOutput(action='done', count=1)
	assert result.thinking is None
	assert result.stop_reason == 'stop'
	assert result.usage is not None
	assert result.usage.prompt_tokens == 11
	assert result.usage.completion_tokens == 7
	assert client.calls == [
		{
			'model': 'qwen3.5-test',
			'messages': [],
			'format': ExampleOutput.model_json_schema(),
			'options': None,
			'think': True,
			'stream': False,
		}
	]
	assert chat.diagnostics_snapshot() == {
		'requests': 1,
		'structured_requests': 1,
		'successes': 1,
		'structured_successes': 1,
		'native_thinking_responses': 1,
		'prompt_tokens': 11,
		'completion_tokens': 7,
		'max_prompt_tokens': 11,
		'max_completion_tokens': 7,
		'stop_reasons': {'stop': 1},
		'failure_categories': {},
	}


@pytest.mark.asyncio
async def test_native_thinking_can_remain_explicitly_disabled_for_old_profiles() -> None:
	client = FakeClient(_response('{"action":"done","count":1}', thinking=''))
	chat = _chat(client, native_thinking=False)

	await chat.ainvoke([], ExampleOutput)

	assert client.calls[0]['think'] is False
	assert chat.diagnostics_snapshot()['native_thinking_responses'] == 0


@pytest.mark.asyncio
async def test_unstructured_compaction_call_is_not_counted_as_schema_validated() -> None:
	chat = _chat(FakeClient(_response('compact neutral history')))

	result = await chat.ainvoke([])

	assert result.completion == 'compact neutral history'
	diagnostics = chat.diagnostics_snapshot()
	assert diagnostics['requests'] == 1
	assert diagnostics['structured_requests'] == 0
	assert diagnostics['successes'] == 1
	assert diagnostics['structured_successes'] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
	('content', 'done_reason', 'category'),
	[
		('', 'stop', 'empty_content'),
		('```json\n{"action":"done","count":1}\n```', 'stop', 'markdown_fence'),
		('<think>reasoning</think>{"action":"done","count":1}', 'stop', 'reasoning_leak'),
		('{not json}', 'stop', 'invalid_json'),
		('{"action":"done"}', 'stop', 'schema_validation'),
		('{"action":"done","count":1}', 'length', 'output_truncated'),
	],
)
async def test_structured_output_failures_are_fail_closed_and_categorized(
	content: str,
	done_reason: str,
	category: str,
) -> None:
	chat = _chat(FakeClient(_response(content, done_reason=done_reason)))

	with pytest.raises(ModelProviderError, match=f'structured_output:{category}') as error:
		await chat.ainvoke([], ExampleOutput)

	if content:
		assert content not in str(error.value)
	assert chat.diagnostics_snapshot()['failure_categories'] == {category: 1}
	assert chat.diagnostics_snapshot()['successes'] == 0


@pytest.mark.asyncio
async def test_provider_failure_does_not_echo_provider_payload() -> None:
	chat = _chat(FakeClient(error=RuntimeError('Failed to connect; secret payload must not persist')))

	with pytest.raises(ModelProviderError, match='provider_connection') as error:
		await chat.ainvoke([], ExampleOutput)

	assert 'secret payload' not in str(error.value)
	assert chat.diagnostics_snapshot()['failure_categories'] == {'provider_connection': 1}
