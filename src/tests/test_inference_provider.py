import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.inference_provider import LocalOllamaProvider, RemoteLlamaCppProvider


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
