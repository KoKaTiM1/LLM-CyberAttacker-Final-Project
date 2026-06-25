from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any, Dict, Optional

import requests

from .llm_utils import build_ollama_metrics, build_llamacpp_metrics, strip_thinking_tags
from .model_config import (
    INFERENCE_BACKEND,
    LOCAL_LLM_MODEL,
    LOCAL_OLLAMA_URL,
    OLLAMA_TIMEOUT_SECONDS,
    REMOTE_LLAMACPP_TIMEOUT_SECONDS,
    REMOTE_LLAMACPP_API_KEY,
    REMOTE_LLAMACPP_API_STYLE,
    REMOTE_LLAMACPP_MAX_TOKENS,
    REMOTE_LLAMACPP_URL,
    REMOTE_LLM_MODEL,
    active_main_model,
    active_rag_model,
    fallback_inference_backend,
)

logger = logging.getLogger(__name__)


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


class FallbackInferenceProvider(InferenceProvider):
    def __init__(self, primary: InferenceProvider, fallback: InferenceProvider):
        self.primary = primary
        self.fallback = fallback

    def health_check(self) -> bool:
        if self.primary.health_check():
            return True
        return self.fallback.health_check()

    def generate(
        self,
        *,
        prompt: str,
        system: str = "",
        model: Optional[str] = None,
        stage: str = "generation",
        temperature: float = 0,
    ) -> InferenceResult:
        try:
            return self.primary.generate(
                prompt=prompt,
                system=system,
                model=model,
                stage=stage,
                temperature=temperature,
            )
        except Exception:
            return self.fallback.generate(
                prompt=prompt,
                system=system,
                model=model,
                stage=stage,
                temperature=temperature,
            )


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
        timeout: int = REMOTE_LLAMACPP_TIMEOUT_SECONDS,
        api_style: str = REMOTE_LLAMACPP_API_STYLE,
        api_key: str = REMOTE_LLAMACPP_API_KEY,
        max_tokens: int = REMOTE_LLAMACPP_MAX_TOKENS,
    ):
        self.url = url
        self.default_model = default_model
        self.timeout = timeout
        self.api_style = api_style
        self.api_key = api_key
        self.max_tokens = max_tokens

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def health_check(self) -> bool:
        try:
            if self.api_style == "openai":
                payload: Dict[str, Any] = {
                    "model": self.default_model,
                    "messages": [{"role": "user", "content": "ping"}],
                    "temperature": 0,
                    "stream": False,
                    "max_tokens": 1,
                }
            else:
                payload = {
                    "prompt": "ping",
                    "temperature": 0,
                    "stream": False,
                    "n_predict": 1,
                }

            response = requests.post(
                self.url,
                json=payload,
                headers=self._headers(),
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            return bool(self._extract_text(data) or data)
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
            payload = self._build_openai_payload(
                prompt=prompt,
                system=system,
                selected_model=selected_model,
                temperature=temperature,
            )
        else:
            payload = {
                "prompt": full_prompt,
                "temperature": temperature,
                "stream": False,
            }
            if self.max_tokens > 0:
                payload["n_predict"] = self.max_tokens

        response = requests.post(self.url, json=payload, headers=self._headers(), timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        text = self._extract_text(data)
        if self.api_style == "openai" and not text and self._has_reasoning_only_response(data):
            logger.warning("Remote model returned reasoning_content with empty content; retrying with /no_think")
            retry_payload = self._build_openai_payload(
                prompt=prompt,
                system=system,
                selected_model=selected_model,
                temperature=temperature,
                disable_thinking=True,
            )
            retry_response = requests.post(
                self.url,
                json=retry_payload,
                headers=self._headers(),
                timeout=self.timeout,
            )
            retry_response.raise_for_status()
            data = retry_response.json()
            text = self._extract_text(data)
        metrics = build_llamacpp_metrics(
            stage=stage,
            model=selected_model,
            prompt_text=full_prompt,
            response_text=text,
            response_payload=data,
        )
        return InferenceResult(text=text, model=selected_model, metrics=metrics, raw=data)

    def _build_openai_payload(
        self,
        *,
        prompt: str,
        system: str,
        selected_model: str,
        temperature: float,
        disable_thinking: bool = False,
    ) -> Dict[str, Any]:
        user_content = prompt
        system_content = system

        if disable_thinking:
            no_think = "/no_think"
            if system_content:
                system_content = f"{no_think}\n{system_content}"
            else:
                user_content = f"{no_think}\n{user_content}"

        payload: Dict[str, Any] = {
            "model": selected_model,
            "messages": [{"role": "user", "content": user_content}],
            "temperature": temperature,
            "stream": False,
        }
        if system_content:
            payload["messages"].insert(0, {"role": "system", "content": system_content})
        if self.max_tokens > 0:
            payload["max_tokens"] = self.max_tokens
        return payload

    @staticmethod
    def _has_reasoning_only_response(data: Dict[str, Any]) -> bool:
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            return False
        first = choices[0]
        if not isinstance(first, dict):
            return False
        message = first.get("message") or {}
        if not isinstance(message, dict):
            return False
        content = str(message.get("content", "") or "").strip()
        reasoning_content = str(message.get("reasoning_content", "") or "").strip()
        return not content and bool(reasoning_content)

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


def _build_provider(backend: str) -> InferenceProvider:
    if backend == "remote":
        return RemoteLlamaCppProvider()
    if backend == "local":
        return LocalOllamaProvider()
    raise ValueError(f"Unsupported inference backend: {backend}")


def get_inference_provider() -> InferenceProvider:
    primary = _build_provider(INFERENCE_BACKEND)
    fallback_backend = fallback_inference_backend()
    if not fallback_backend:
        return primary
    fallback = _build_provider(fallback_backend)
    return FallbackInferenceProvider(primary=primary, fallback=fallback)


def get_main_model() -> str:
    return active_main_model()


def get_rag_model() -> str:
    return active_rag_model()
