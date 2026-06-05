import os
import sys
from types import SimpleNamespace


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.llm_utils import (
    approximate_token_count,
    build_langchain_metrics,
    build_ollama_metrics,
    merge_metric_totals,
)


def test_build_ollama_metrics_uses_backend_counts():
    payload = {
        "prompt_eval_count": 120,
        "eval_count": 60,
        "eval_duration": 30_000_000_000,
        "total_duration": 45_000_000_000,
    }

    metrics = build_ollama_metrics(
        stage="file_analysis",
        model="test-model",
        prompt_text="x" * 20,
        response_text="y" * 20,
        response_payload=payload,
    )

    assert metrics["prompt_tokens"] == 120
    assert metrics["response_tokens"] == 60
    assert metrics["tokens_per_second"] == 2.0
    assert metrics["total_context_tokens"] == 120


def test_build_langchain_metrics_reads_response_metadata():
    message = SimpleNamespace(
        response_metadata={
            "prompt_eval_count": 80,
            "eval_count": 40,
            "eval_duration": 10_000_000_000,
            "total_duration": 15_000_000_000,
        },
        usage_metadata={},
    )

    metrics = build_langchain_metrics(
        stage="rag_llm_step",
        model="rag-model",
        prompt_text="hello",
        response_text="world",
        message=message,
        retrieved_context_text="ctx",
    )

    assert metrics["prompt_tokens"] == 80
    assert metrics["response_tokens"] == 40
    assert metrics["rag_context_tokens"] == approximate_token_count("ctx")
    assert metrics["tokens_per_second"] == 4.0


def test_merge_metric_totals_accumulates_counts():
    first = {"prompt_tokens": 10, "response_tokens": 5, "rag_context_tokens": 3, "total_context_tokens": 13}
    second = {"prompt_tokens": 7, "response_tokens": 2, "rag_context_tokens": 1, "total_context_tokens": 8}

    totals = merge_metric_totals(first, second)

    assert totals == {
        "prompt_tokens": 17,
        "response_tokens": 7,
        "rag_context_tokens": 4,
        "total_context_tokens": 21,
    }
