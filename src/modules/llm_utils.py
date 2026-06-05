import math
import re
from typing import Any, Dict, Optional


def strip_thinking_tags(text: str) -> str:
    """Remove <think>...</think> blocks produced by reasoning models (e.g. DeepSeek-R1)."""
    return re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()


def approximate_token_count(text: str) -> int:
    """Cheap token estimate when the backend does not return token counts."""
    if not text:
        return 0
    return max(1, math.ceil(len(text) / 4))


def _safe_ns_to_seconds(value: Any) -> float:
    try:
        numeric = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    return numeric / 1_000_000_000 if numeric > 0 else 0.0


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def build_ollama_metrics(
    *,
    stage: str,
    model: str,
    prompt_text: str = "",
    response_text: str = "",
    response_payload: Optional[Dict[str, Any]] = None,
    retrieved_context_text: str = "",
) -> Dict[str, Any]:
    """Normalize Ollama response metrics into one structure."""
    payload = response_payload or {}
    prompt_eval_count = _safe_int(payload.get("prompt_eval_count"))
    eval_count = _safe_int(payload.get("eval_count"))
    eval_duration_seconds = _safe_ns_to_seconds(payload.get("eval_duration"))
    total_duration_seconds = _safe_ns_to_seconds(payload.get("total_duration"))

    prompt_tokens = prompt_eval_count or approximate_token_count(prompt_text)
    response_tokens = eval_count or approximate_token_count(response_text)
    rag_context_tokens = approximate_token_count(retrieved_context_text)
    total_context_tokens = prompt_tokens + rag_context_tokens
    tokens_per_second = round(response_tokens / eval_duration_seconds, 2) if eval_duration_seconds > 0 else 0.0

    return {
        "stage": stage,
        "model": model,
        "prompt_tokens": prompt_tokens,
        "response_tokens": response_tokens,
        "rag_context_tokens": rag_context_tokens,
        "total_context_tokens": total_context_tokens,
        "tokens_per_second": tokens_per_second,
        "prompt_eval_count": prompt_eval_count,
        "eval_count": eval_count,
        "eval_duration_seconds": round(eval_duration_seconds, 2),
        "total_duration_seconds": round(total_duration_seconds, 2),
    }


def build_langchain_metrics(
    *,
    stage: str,
    model: str,
    prompt_text: str = "",
    response_text: str = "",
    message: Any = None,
    retrieved_context_text: str = "",
) -> Dict[str, Any]:
    """Normalize LangChain/Ollama AIMessage metadata into the same structure."""
    response_metadata = getattr(message, "response_metadata", {}) or {}
    usage_metadata = getattr(message, "usage_metadata", {}) or {}

    prompt_eval_count = _safe_int(
        usage_metadata.get("input_tokens") or response_metadata.get("prompt_eval_count")
    )
    eval_count = _safe_int(
        usage_metadata.get("output_tokens") or response_metadata.get("eval_count")
    )
    eval_duration_seconds = _safe_ns_to_seconds(response_metadata.get("eval_duration"))
    total_duration_seconds = _safe_ns_to_seconds(response_metadata.get("total_duration"))

    prompt_tokens = prompt_eval_count or approximate_token_count(prompt_text)
    response_tokens = eval_count or approximate_token_count(response_text)
    rag_context_tokens = approximate_token_count(retrieved_context_text)
    total_context_tokens = prompt_tokens + rag_context_tokens
    tokens_per_second = round(response_tokens / eval_duration_seconds, 2) if eval_duration_seconds > 0 else 0.0

    return {
        "stage": stage,
        "model": model,
        "prompt_tokens": prompt_tokens,
        "response_tokens": response_tokens,
        "rag_context_tokens": rag_context_tokens,
        "total_context_tokens": total_context_tokens,
        "tokens_per_second": tokens_per_second,
        "prompt_eval_count": prompt_eval_count,
        "eval_count": eval_count,
        "eval_duration_seconds": round(eval_duration_seconds, 2),
        "total_duration_seconds": round(total_duration_seconds, 2),
    }


def merge_metric_totals(existing: Optional[Dict[str, Any]], metric: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate prompt/output token usage across workflow steps."""
    totals = dict(existing or {})
    metric = metric or {}

    totals["prompt_tokens"] = _safe_int(totals.get("prompt_tokens")) + _safe_int(metric.get("prompt_tokens"))
    totals["response_tokens"] = _safe_int(totals.get("response_tokens")) + _safe_int(metric.get("response_tokens"))
    totals["rag_context_tokens"] = _safe_int(totals.get("rag_context_tokens")) + _safe_int(metric.get("rag_context_tokens"))
    totals["total_context_tokens"] = _safe_int(totals.get("total_context_tokens")) + _safe_int(metric.get("total_context_tokens"))
    return totals


def format_metric_log(prefix: str, metric: Optional[Dict[str, Any]]) -> str:
    """Render one concise metrics line for execution_log."""
    data = metric or {}
    return (
        f"{prefix}: model={data.get('model', 'unknown')}, "
        f"context~{data.get('total_context_tokens', 0)} tok, "
        f"prompt~{data.get('prompt_tokens', 0)} tok, "
        f"rag~{data.get('rag_context_tokens', 0)} tok, "
        f"output~{data.get('response_tokens', 0)} tok, "
        f"speed={data.get('tokens_per_second', 0)} tok/s"
    )
