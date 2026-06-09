from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import requests

from .llm_utils import build_ollama_metrics, build_llamacpp_metrics, strip_thinking_tags
from .model_config import (
    INFERENCE_BACKEND,
    LOCAL_LLM_MODEL,
    LOCAL_OLLAMA_URL,
    OLLAMA_TIMEOUT_SECONDS,
    REMOTE_LLAMACPP_API_KEY,
    REMOTE_LLAMACPP_API_STYLE,
    REMOTE_LLAMACPP_URL,
    REMOTE_LLM_MODEL,
    active_main_model,
    active_rag_model,
)


@dataclass
class InferenceResult:
    text: str
    model: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_ollama_like(self) -> Dict[str, Any]:
        payload = dict(self.raw or {})
        payload["response"] = self.text
        payload["model"] = self.model
        payload["metrics"] = self.metrics
        return payload


class InferenceProvider:
    def health_check(self) -> bool:
        raise NotImplementedError

    def generate(
        self,
        *,
        prompt: str,
        system: str = "",
        model: Optional[str] = None,
        stage: str = "generation",
        temperature: float = 0,
    ) -> InferenceResult:
        raise NotImplementedError


class LocalOllamaProvider(InferenceProvider):
    def __init__(
        self,
        *,
        url: str = LOCAL_OLLAMA_URL,
        default_model: str = LOCAL_LLM_MODEL,
        timeout: int = OLLAMA_TIMEOUT_SECONDS,
    ):
        self.url = url
        self.default_model = default_model
        self.timeout = timeout

    def health_check(self) -> bool:
        try:
            result = self.generate(prompt="ping", stage="health_check")
            return bool(result.text or result.raw)
        except Exception:
            return False

    def generate(
        self,
        *,
        prompt: str,
        system: str = "",
        model: Optional[str] = None,
        stage: str = "generation",
        temperature: float = 0,
    ) -> InferenceResult:
        selected_model = model or self.default_model
        payload: Dict[str, Any] = {
            "model": selected_model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system

        response = requests.post(self.url, json=payload, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        text = strip_thinking_tags(str(data.get("response", ""))).strip()
        metrics = build_ollama_metrics(
            stage=stage,
            model=selected_model,
            prompt_text=f"{system}\n\n{prompt}" if system else prompt,
            response_text=text,
            response_payload=data,
        )
        return InferenceResult(text=text, model=selected_model, metrics=metrics, raw=data)


class RemoteLlamaCppProvider(InferenceProvider):
    def __init__(
        self,
        *,
        url: str = REMOTE_LLAMACPP_URL,
        default_model: str = REMOTE_LLM_MODEL,
        timeout: int = OLLAMA_TIMEOUT_SECONDS,
        api_style: str = REMOTE_LLAMACPP_API_STYLE,
        api_key: str = REMOTE_LLAMACPP_API_KEY,
    ):
        self.url = url
        self.default_model = default_model
        self.timeout = timeout
        self.api_style = api_style
        self.api_key = api_key

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def health_check(self) -> bool:
        try:
            result = self.generate(prompt="ping", stage="health_check")
            return bool(result.text or result.raw)
        except Exception:
            return False

    def generate(
        self,
        *,
        prompt: str,
        system: str = "",
        model: Optional[str] = None,
        stage: str = "generation",
        temperature: float = 0,
    ) -> InferenceResult:
        selected_model = model or self.default_model
        full_prompt = f"{system}\n\n{prompt}" if system else prompt

        if self.api_style == "openai":
            payload: Dict[str, Any] = {
                "model": selected_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "stream": False,
            }
            if system:
                payload["messages"].insert(0, {"role": "system", "content": system})
        else:
            payload = {
                "prompt": full_prompt,
                "temperature": temperature,
                "stream": False,
            }

        response = requests.post(self.url, json=payload, headers=self._headers(), timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        text = self._extract_text(data)
        metrics = build_llamacpp_metrics(
            stage=stage,
            model=selected_model,
            prompt_text=full_prompt,
            response_text=text,
            response_payload=data,
        )
        return InferenceResult(text=text, model=selected_model, metrics=metrics, raw=data)

    @staticmethod
    def _extract_text(data: Dict[str, Any]) -> str:
        if "content" in data:
            return strip_thinking_tags(str(data.get("content", ""))).strip()
        if "response" in data:
            return strip_thinking_tags(str(data.get("response", ""))).strip()
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message") or {}
                if isinstance(message, dict) and "content" in message:
                    return strip_thinking_tags(str(message.get("content", ""))).strip()
                if "text" in first:
                    return strip_thinking_tags(str(first.get("text", ""))).strip()
        return ""


def get_inference_provider() -> InferenceProvider:
    if INFERENCE_BACKEND == "remote":
        return RemoteLlamaCppProvider()
    if INFERENCE_BACKEND == "local":
        return LocalOllamaProvider()
    raise ValueError(f"Unsupported INFERENCE_BACKEND: {INFERENCE_BACKEND}")


def get_main_model() -> str:
    return active_main_model()


def get_rag_model() -> str:
    return active_rag_model()
