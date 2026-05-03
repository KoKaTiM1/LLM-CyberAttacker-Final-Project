import re


def strip_thinking_tags(text: str) -> str:
    """Remove <think>...</think> blocks produced by reasoning models (e.g. DeepSeek-R1)."""
    return re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
