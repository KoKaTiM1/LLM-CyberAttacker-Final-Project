from pathlib import Path
from datetime import datetime
import json
import logging
import re

from .inference_provider import get_main_model
from .services.inference_service import InferenceService

logger = logging.getLogger(__name__)


def getFile(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        print("file not found")
        return False

    if path.suffix.lower() not in [".c", ".txt"]:
        print("this is not C file")
        return False

    try:
        file_content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"failed to read file: {e}")
        return False

    if len(file_content.strip()) == 0:
        print("empty file")
        return False
    return True


def checkConnectionWithOllama() -> bool:
    try:
        if InferenceService().health_check():
            print(f"Connected to inference backend with model {get_main_model()}.")
            return True
    except Exception as e:
        print(f"Request failed: {e}")
    return False


def checkAPIconnectionWithAgent() -> bool:
    return checkConnectionWithOllama()


def _clean_structured_response(response_text: str) -> str:
    response_text = response_text.strip()
    response_text = re.sub(r"^```(?:json)?\s*", "", response_text, flags=re.IGNORECASE)
    response_text = re.sub(r"\s*```$", "", response_text)
    return response_text.strip()


def _write_analysis_trace(
    *,
    stage: str,
    model: str,
    prompt: str,
    response_text: str,
    raw_payload,
    error_message: str = "",
) -> None:
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    trace_path = logs_dir / f"analysis_trace_{stage}_{ts}.json"
    trace = {
        "timestamp": ts,
        "stage": stage,
        "model": model,
        "prompt": prompt,
        "response_text": response_text,
        "raw_payload": raw_payload,
        "error_message": error_message,
    }
    trace_path.write_text(json.dumps(trace, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    logger.info(f"📝 Analysis trace saved to {trace_path}")


def sendToLLMWithDynamicPrompt(system_prompt: str, user_prompt: str, model: str = None):
    """
    Send request to the configured inference provider with separate system and user prompts.
    Keeps the legacy Ollama-like return shape used by the workflow.
    """
    selected_model = model or get_main_model()
    combined_prompt = f"{system_prompt}\n\n{user_prompt}"

    logger.info("=" * 60)
    logger.info("[sendToLLMWithDynamicPrompt] SENDING REQUEST TO LLM")
    logger.info("=" * 60)
    logger.info(f"Model: {selected_model}")
    logger.info(f"Prompt length: {len(combined_prompt)} chars")
    logger.info("--- PROMPT START ---")
    logger.info(combined_prompt)
    logger.info("--- PROMPT END ---")

    try:
        result = InferenceService().generate_main(
            prompt=user_prompt,
            system=system_prompt,
            model=selected_model,
            stage="cve_analysis",
        )
        payload = result.to_ollama_like()
        payload["response"] = _clean_structured_response(result.text)
        logger.info("--- LLM RESPONSE START ---")
        logger.info(payload["response"])
        logger.info("--- LLM RESPONSE END ---")
        _write_analysis_trace(
            stage="cve_analysis",
            model=selected_model,
            prompt=combined_prompt,
            response_text=payload["response"],
            raw_payload=result.raw,
        )
        return payload
    except Exception as e:
        _write_analysis_trace(
            stage="cve_analysis",
            model=selected_model,
            prompt=combined_prompt,
            response_text="",
            raw_payload={},
            error_message=str(e),
        )
        logger.error(f"Request failed: {e}")
        return None


def sendToLLM(content, rag_context: str = ""):
    prompt = (
        "You are a security code reviewer for C files. "
        "Please analyze the following C file and identify potential vulnerabilities. "
        "Return ONLY valid JSON. "
        "Do not include markdown fences, comments, prose, bullets, or explanatory text before or after the JSON. "
        "If you are unsure about a field, use an empty string or \"Unknown\" instead of adding explanation outside the JSON. "
        "Return the results in valid JSON format with EXACTLY these field names: "
        "'Type', 'Location', 'Severity', 'Explanation', and 'SuggestedFix'. "
        "Use this exact format:\n"
        "{\n"
        '  "vulnerabilities": [\n'
        "    {\n"
        '      "Type": "vulnerability type",\n'
        '      "Location": "line number or function",\n'
        '      "Severity": "High/Medium/Low",\n'
        '      "Explanation": "detailed explanation",\n'
        '      "SuggestedFix": "how to fix it"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        f"{content}"
    )

    if rag_context:
        prompt += (
            "\n\n[Relevant RAG Context]\n"
            "Use the following context only if it is directly relevant to the code under review. "
            "Do not copy it verbatim into the output. "
            "Ignore it if it is generic, repetitive, or not specific to this file.\n"
            f"{rag_context[:3000]}"
        )

    logger.info("=" * 60)
    logger.info("[sendToLLM] SENDING REQUEST TO LLM")
    logger.info("=" * 60)
    logger.info(f"Prompt length: {len(prompt)} chars")
    logger.info("--- PROMPT START ---")
    logger.info(prompt)
    logger.info("--- PROMPT END ---")

    try:
        result = InferenceService().generate_main(
            prompt=prompt,
            model=get_main_model(),
            stage="file_analysis",
        )
        payload = result.to_ollama_like()
        payload["response"] = _clean_structured_response(result.text)
        logger.info("--- LLM RESPONSE START ---")
        logger.info(payload["response"])
        logger.info("--- LLM RESPONSE END ---")
        if not payload["response"]:
            logger.warning("LLM response text was empty after extraction")
            logger.warning(f"Raw response keys: {list((payload or {}).keys())}")
            logger.warning(f"Raw response preview: {str(result.raw)[:1200]}")
        _write_analysis_trace(
            stage="file_analysis",
            model=get_main_model(),
            prompt=prompt,
            response_text=payload["response"],
            raw_payload=result.raw,
        )
        return payload
    except Exception as e:
        _write_analysis_trace(
            stage="file_analysis",
            model=get_main_model(),
            prompt=prompt,
            response_text="",
            raw_payload={},
            error_message=str(e),
        )
        logger.error(f"Request failed: {e}")
        return None
