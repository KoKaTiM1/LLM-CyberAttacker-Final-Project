from __future__ import annotations

from typing import Optional

from ..inference_provider import (
    InferenceProvider,
    InferenceResult,
    get_inference_provider,
    get_main_model,
    get_rag_model,
)


class InferenceService:
    """Application-facing inference service used by analysis, RAG, and generation."""

    def __init__(self, provider: Optional[InferenceProvider] = None):
        self.provider = provider or get_inference_provider()

    def health_check(self) -> bool:
        return self.provider.health_check()

    def generate_main(
        self,
        *,
        prompt: str,
        system: str = "",
        stage: str = "generation",
        model: Optional[str] = None,
    ) -> InferenceResult:
        return self.provider.generate(
            prompt=prompt,
            system=system,
            model=model or get_main_model(),
            stage=stage,
        )

    def generate_rag(
        self,
        *,
        prompt: str,
        stage: str = "rag_llm_step",
        model: Optional[str] = None,
    ) -> InferenceResult:
        return self.provider.generate(
            prompt=prompt,
            model=model or get_rag_model(),
            stage=stage,
        )
