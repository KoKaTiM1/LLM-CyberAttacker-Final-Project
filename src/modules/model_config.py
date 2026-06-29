import os
from pathlib import Path


def _load_project_env() -> None:
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_project_env()

OLLAMA_MODEL = "huihui_ai/deepseek-r1-abliterated:14b-qwen-distill"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "600"))
REMOTE_LLAMACPP_TIMEOUT_SECONDS = int(os.getenv("REMOTE_LLAMACPP_TIMEOUT_SECONDS", str(OLLAMA_TIMEOUT_SECONDS)))
SANDBOX_COMMAND_TIMEOUT_SECONDS = int(os.getenv("SANDBOX_COMMAND_TIMEOUT_SECONDS", "900"))

INFERENCE_BACKEND = os.getenv("INFERENCE_BACKEND", "local").strip().lower()
FALLBACK_INFERENCE_BACKEND = os.getenv("FALLBACK_INFERENCE_BACKEND", "").strip().lower()

LOCAL_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", OLLAMA_MODEL)
LOCAL_RAG_LLM_MODEL = os.getenv("LOCAL_RAG_LLM_MODEL", os.getenv("RAG_LLM_MODEL", "llama3.2:1b"))
LOCAL_OLLAMA_URL = os.getenv("LOCAL_OLLAMA_URL", OLLAMA_URL)

REMOTE_LLM_MODEL = os.getenv("REMOTE_LLM_MODEL", LOCAL_LLM_MODEL)
REMOTE_RAG_LLM_MODEL = os.getenv("REMOTE_RAG_LLM_MODEL", REMOTE_LLM_MODEL)
REMOTE_LLAMACPP_URL = os.getenv("REMOTE_LLAMACPP_URL", "http://localhost:8080/completion")
REMOTE_LLAMACPP_API_STYLE = os.getenv("REMOTE_LLAMACPP_API_STYLE", "raw").strip().lower()
REMOTE_LLAMACPP_API_KEY = os.getenv("REMOTE_LLAMACPP_API_KEY", "")
REMOTE_LLAMACPP_MAX_TOKENS = int(os.getenv("REMOTE_LLAMACPP_MAX_TOKENS", "0"))


def active_main_model() -> str:
    return REMOTE_LLM_MODEL if INFERENCE_BACKEND == "remote" else LOCAL_LLM_MODEL


def active_rag_model() -> str:
    return REMOTE_RAG_LLM_MODEL if INFERENCE_BACKEND == "remote" else LOCAL_RAG_LLM_MODEL


def fallback_inference_backend() -> str:
    if not FALLBACK_INFERENCE_BACKEND or FALLBACK_INFERENCE_BACKEND == INFERENCE_BACKEND:
        return ""
    return FALLBACK_INFERENCE_BACKEND

MODEL_PROFILES = {
    "model": {
        "prompt_style": "explicit_pwntools",
        "description": "Remote cluster alias mapped to the explicit pwntools prompt profile",
    },
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
