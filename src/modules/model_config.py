import os

OLLAMA_MODEL = "huihui_ai/deepseek-r1-abliterated:14b-qwen-distill"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "180"))

MODEL_PROFILES = {
    "huihui_ai/deepseek-r1-abliterated:14b-qwen-distill": {
        "prompt_style": "explicit_pwntools",
        "description": "Abliterated DeepSeek-R1 14B — no refusals, strong code quality",
    },
    "dolphin3": {
        "prompt_style": "explicit_pwntools",
        "description": "Uncensored model — needs explicit pwntools structure to avoid pseudo-code",
    },
    "gpt-oss:20b": {
        "prompt_style": "research_framing",
        "description": "Safety-trained model — responds to educational/research framing",
    },
    "default": {
        "prompt_style": "research_framing",
        "description": "Fallback for unrecognized models",
    },
}
