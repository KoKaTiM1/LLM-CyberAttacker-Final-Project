import os
import sys
import importlib


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.inference_provider import (
    FallbackInferenceProvider,
    InferenceResult,
    LocalOllamaProvider,
    RemoteLlamaCppProvider,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


def test_local_ollama_provider_returns_legacy_shape(monkeypatch):
    def fake_post(url, json, timeout):
        assert json["model"] == "local-model"
        assert json["prompt"] == "hello"
        return FakeResponse(
            {
                "response": "world",
                "prompt_eval_count": 4,
                "eval_count": 2,
                "eval_duration": 1_000_000_000,
            }
        )

    monkeypatch.setattr("modules.inference_provider.requests.post", fake_post)

    result = LocalOllamaProvider(url="http://local", default_model="local-model").generate(
        prompt="hello",
        stage="unit",
    )

    assert result.text == "world"
    assert result.model == "local-model"
    assert result.metrics["tokens_per_second"] == 2.0
    assert result.to_ollama_like()["response"] == "world"


def test_remote_llamacpp_provider_reads_raw_completion(monkeypatch):
    def fake_post(url, json, headers, timeout):
        assert url == "http://cluster/completion"
        assert json["prompt"] == "system\n\nhello"
        return FakeResponse(
            {
                "content": "remote answer",
                "tokens_evaluated": 10,
                "tokens_predicted": 5,
                "timings": {"predicted_per_second": 40},
            }
        )

    monkeypatch.setattr("modules.inference_provider.requests.post", fake_post)

    result = RemoteLlamaCppProvider(
        url="http://cluster/completion",
        default_model="remote-model",
        api_style="raw",
    ).generate(
        prompt="hello",
        system="system",
        stage="unit",
    )

    assert result.text == "remote answer"
    assert result.model == "remote-model"
    assert result.metrics["prompt_tokens"] == 10
    assert result.metrics["tokens_per_second"] == 40


def test_remote_openai_provider_sends_max_tokens_when_configured(monkeypatch):
    captured = {}

    def fake_post(url, json, headers, timeout):
        captured["json"] = json
        return FakeResponse(
            {
                "choices": [
                    {
                        "message": {"content": "remote answer"},
                    }
                ]
            }
        )

    monkeypatch.setattr("modules.inference_provider.requests.post", fake_post)

    result = RemoteLlamaCppProvider(
        url="http://cluster/v1/chat/completions",
        default_model="remote-model",
        api_style="openai",
        max_tokens=321,
    ).generate(
        prompt="hello",
        system="system",
        stage="unit",
    )

    assert result.text == "remote answer"
    assert captured["json"]["max_tokens"] == 321


def test_remote_openai_provider_retries_with_no_think_on_reasoning_only_response(monkeypatch):
    calls = []

    def fake_post(url, json, headers, timeout):
        calls.append(json)
        if len(calls) == 1:
            return FakeResponse(
                {
                    "choices": [
                        {
                            "message": {
                                "content": "",
                                "reasoning_content": "the " * 200,
                            }
                        }
                    ]
                }
            )
        return FakeResponse(
            {
                "choices": [
                    {
                        "message": {"content": "{\"vulnerabilities\": []}"},
                    }
                ]
            }
        )

    monkeypatch.setattr("modules.inference_provider.requests.post", fake_post)

    result = RemoteLlamaCppProvider(
        url="http://cluster/v1/chat/completions",
        default_model="remote-model",
        api_style="openai",
        max_tokens=321,
    ).generate(
        prompt="hello",
        system="system",
        stage="unit",
    )

    assert result.text == '{"vulnerabilities": []}'
    assert len(calls) == 2
    assert calls[1]["messages"][0]["content"].startswith("/no_think\n")


def test_remote_openai_health_check_uses_single_token_probe(monkeypatch):
    calls = {}

    def fake_post(url, json, headers, timeout):
        calls["url"] = url
        calls["json"] = json
        calls["timeout"] = timeout
        return FakeResponse(
            {
                "choices": [
                    {
                        "message": {"content": "ok"},
                    }
                ]
            }
        )

    monkeypatch.setattr("modules.inference_provider.requests.post", fake_post)

    provider = RemoteLlamaCppProvider(
        url="http://cluster/v1/chat/completions",
        default_model="remote-model",
        api_style="openai",
        timeout=321,
    )

    assert provider.health_check() is True
    assert calls["url"] == "http://cluster/v1/chat/completions"
    assert calls["json"]["max_tokens"] == 1
    assert calls["json"]["messages"][0]["content"] == "ping"
    assert calls["timeout"] == 321


def test_fallback_provider_uses_local_when_remote_fails():
    class FailingProvider:
        def health_check(self):
            return False

        def generate(self, **kwargs):
            raise RuntimeError("remote down")

    class LocalProvider:
        def health_check(self):
            return True

        def generate(self, **kwargs):
            return InferenceResult(text="local answer", model="local-model", metrics={}, raw={})

    provider = FallbackInferenceProvider(FailingProvider(), LocalProvider())

    result = provider.generate(prompt="hello", stage="unit")

    assert result.text == "local answer"
    assert provider.health_check() is True


def test_remote_timeout_can_be_configured_via_env(monkeypatch):
    monkeypatch.setenv("REMOTE_LLAMACPP_TIMEOUT_SECONDS", "321")
    monkeypatch.setenv("INFERENCE_BACKEND", "remote")
    monkeypatch.setenv("FALLBACK_INFERENCE_BACKEND", "")

    import modules.model_config as model_config
    import modules.inference_provider as inference_provider

    importlib.reload(model_config)
    importlib.reload(inference_provider)

    provider = inference_provider.RemoteLlamaCppProvider()

    assert provider.timeout == 321
