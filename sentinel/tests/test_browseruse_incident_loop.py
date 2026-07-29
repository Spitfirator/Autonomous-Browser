import asyncio
import inspect
from types import MethodType, SimpleNamespace

import pytest
from browser_use import Agent
from browser_use.agent.views import ActionResult, AgentState, AgentStepInfo
from browser_use.llm.messages import SystemMessage, UserMessage

from server.config import ConfigStore
from server.governance.governed_llm import GovernedLLM, RunContext
from server.governance.handover import HandoverManager


class _InnerLLM:
	model = 'inner'
	provider = 'test'
	name = 'inner'

	def __init__(self) -> None:
		self.calls: list[list[object]] = []

	async def ainvoke(self, messages, output_format=None, **kwargs):  # noqa: ANN001, ANN201
		self.calls.append(messages)
		return SimpleNamespace(usage=None)


class _History:
	def __init__(self) -> None:
		self.history: list[object] = []

	def is_done(self) -> bool:
		return False


async def _wait_until(predicate) -> None:  # noqa: ANN001
	for _ in range(50):
		if predicate():
			return
		await asyncio.sleep(0)
	raise AssertionError('condition was not reached')


@pytest.mark.asyncio
async def test_browseruse_recaptures_after_incident_without_recording_aborted_step(
	tmp_path,
) -> None:
	"""Exercise BrowserUse 0.13.2's real step/finalize interruption boundary."""

	config = ConfigStore(tmp_path / 'config.json')
	config.update(
		{
			'policies': {
				'prompt_injection': {
					'browser_sanitize': True,
					'alert_after_sanitize': False,
				}
			}
		}
	)
	events = []
	inner = _InnerLLM()
	context = RunContext('incident-loop', 5)
	handovers = HandoverManager(events.append)
	governed = GovernedLLM(  # type: ignore[arg-type]
		inner,
		events.append,
		context,
		config_store=config,
		handovers=handovers,
		handover_timeout_s=1,
	)
	unsafe_messages = [
		SystemMessage(content='trusted'),
		UserMessage(
			content=(
				'<user_request>Review the settings.</user_request>'
				'<browser_state>Current tab: ab12\n'
				'Personal Access Tokens\n'
				'No active entries.\n'
				'Add a new token\n'
				'[9]<button aria-label=Copy feed token>Copy feed token</button>\n'
				'</browser_state>'
			)
		),
	]
	fresh_messages = [
		SystemMessage(content='trusted'),
		UserMessage(
			content=(
				'<user_request>Review the settings.</user_request>'
				'<browser_state>Current tab: ab12\n'
				'Fresh ordinary settings page.</browser_state>'
			)
		),
	]

	agent = object.__new__(Agent)
	agent.browser_session = None
	agent.state = AgentState()
	agent.settings = SimpleNamespace(step_timeout=1, use_judge=False)
	agent.history = _History()
	agent._message_manager = SimpleNamespace(last_state_message_text=None)
	agent.register_done_callback = None

	captured: list[str] = []
	recorded: list[str] = []
	fresh_captured = asyncio.Event()
	allow_fresh_call = asyncio.Event()

	async def prepare_context(_self, _step_info):  # noqa: ANN001, ANN202
		label = 'quarantined' if not captured else 'fresh'
		captured.append(label)
		if label == 'fresh':
			fresh_captured.set()
			await allow_fresh_call.wait()
		return SimpleNamespace(label=label)

	async def get_next_action(_self, browser_state):  # noqa: ANN001, ANN202
		messages = unsafe_messages if browser_state.label == 'quarantined' else fresh_messages
		await governed.ainvoke(messages)

	async def execute_actions(self):  # noqa: ANN001, ANN202
		self.state.last_result = [ActionResult(extracted_content='fresh action executed')]

	async def no_op(*_args, **_kwargs) -> None:
		return None

	async def make_history_item(_self, _output, browser_state, _result, _metadata, **_kwargs):  # noqa: ANN001, ANN202
		recorded.append(browser_state.label)
		agent.history.history.append(browser_state.label)

	agent._prepare_context = MethodType(prepare_context, agent)
	agent._get_next_action = MethodType(get_next_action, agent)
	agent._execute_actions = MethodType(execute_actions, agent)
	agent._post_process = MethodType(no_op, agent)
	agent._demo_mode_log = MethodType(no_op, agent)
	agent._make_history_item = MethodType(make_history_item, agent)
	agent._log_step_completion_summary = MethodType(lambda *_args: None, agent)
	agent.save_file_system_state = MethodType(lambda *_args: None, agent)
	# Skip observability wrappers while retaining BrowserUse's real step,
	# InterruptedError handling, finalizer, and loop-driver boundary.
	agent.step = MethodType(inspect.unwrap(Agent.step), agent)

	async def run_until_one_step_is_recorded() -> int:
		attempts = 0
		while agent.state.n_steps <= 1:
			if attempts >= 2:
				raise AssertionError('BrowserUse did not complete after the fresh observation')
			current_step = agent.state.n_steps - 1
			is_done = await Agent._execute_step(
				agent,
				current_step,
				1,
				AgentStepInfo(step_number=current_step, max_steps=1),
			)
			assert not is_done
			attempts += 1
		return attempts

	loop_task = asyncio.create_task(run_until_one_step_is_recorded())
	await _wait_until(lambda: bool(handovers.pending_list()))
	request = handovers.pending_list()[0]

	assert captured == ['quarantined']
	assert inner.calls == []
	assert agent.state.n_steps == 1
	assert recorded == []

	assert handovers.complete(request['handover_id'], None)
	await fresh_captured.wait()

	# Returning control discards the held prompt. BrowserUse has started a new
	# capture, but has not recorded or counted the interrupted iteration.
	assert captured == ['quarantined', 'fresh']
	assert inner.calls == []
	assert agent.state.n_steps == 1
	assert recorded == []
	assert agent.state.consecutive_failures == 0

	allow_fresh_call.set()
	assert await loop_task == 2

	assert agent.state.n_steps == 2
	assert recorded == ['fresh']
	assert len(inner.calls) == 1
	assert 'Fresh ordinary settings page.' in inner.calls[0][1].text
	assert 'Copy feed token' not in inner.calls[0][1].text
	assert context.llm_calls == 1
