from pathlib import Path
import logging

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
    if response_text.startswith("```json"):
        response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
    elif response_text.startswith("```"):
        response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
    return response_text.strip()


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
        return payload
    except Exception as e:
        logger.error(f"Request failed: {e}")
        return None


def sendToLLM(content):
    prompt = (
        "You are a security code reviewer for C files. "
        "Please analyze the following C file and identify potential vulnerabilities. "
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
        return payload
    except Exception as e:
        logger.error(f"Request failed: {e}")
        return None
