from server.config import default_model_config
from server.llm_factory import build_chat
from server.ollama_chat import SentinelChatOllama


def test_qwen_is_default_with_optional_gemini_fallback() -> None:
	config = default_model_config()
	assert config.provider == 'ollama'
	assert config.model == 'qwen3.5-agentdojo:4b'
	assert config.temperature == 0.7
	assert config.throttle is None
	assert config.fallback is not None
	assert config.fallback.provider == 'gemini'
	assert config.fallback.model == 'gemini-3.1-flash-lite'


def test_ollama_build_needs_no_api_key_and_uses_bounded_options(monkeypatch) -> None:
	monkeypatch.delenv('OLLAMA_HOST', raising=False)
	chat = build_chat(default_model_config())
	assert isinstance(chat, SentinelChatOllama)
	assert chat.model == 'qwen3.5-agentdojo:4b'
	assert chat.timeout == 180
	assert chat.ollama_options == {
		'num_ctx': 8192,
		'num_predict': 1024,
		'temperature': 0.7,
		'top_k': 20,
		'top_p': 0.8,
		'presence_penalty': 1.5,
		'seed': 0,
	}
