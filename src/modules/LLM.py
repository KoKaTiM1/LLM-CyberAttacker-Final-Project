from pathlib import Path
import requests
import logging
from .Agent import resultsFromLLM
from .model_config import OLLAMA_MODEL, OLLAMA_URL, OLLAMA_TIMEOUT_SECONDS
from .llm_utils import strip_thinking_tags, build_ollama_metrics

logger = logging.getLogger(__name__)


def getFile(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        print("file not found")
        return False

    if path.suffix.lower() not in [".c", ".txt"]:
        print("this is not C file")
        return False

    try:
        fileContent = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"failed to read file: {e}")
        return False

    if len(fileContent.strip()) == 0:
        print("empty file")
        return False
    return True

def checkConnectionWithOllama() -> bool:
        data = {
            "model": OLLAMA_MODEL,
            "prompt": "ping",
            "stream": False
        }
        try:
            response = requests.post(OLLAMA_URL, json=data, timeout=OLLAMA_TIMEOUT_SECONDS)
            if response.status_code == 200:
                print(f"Connected to {OLLAMA_MODEL} via Ollama.")
                print(response.json())
                return True
            else:
                print(f"Error: {response.status_code}, {response.text}")
                return False
        except Exception as e:
            print(f"Request failed: {e}")
            return False
def checkAPIconnectionWithAgent() -> bool:
    # For Ollama, we can use the same connection check as checkConnectionWithOllama
    return checkConnectionWithOllama()

def sendToLLMWithDynamicPrompt(system_prompt: str, user_prompt: str, model: str = None):
    """
    Send request to LLM with separate system and user prompts (dynamic prompts).
    This function is used by the Orchestrator to send customized prompts.

    Args:
        system_prompt: The system/role prompt (e.g., expert profile)
        user_prompt: The user's task/question prompt (e.g., CVE analysis task)
        model: The model to use (default: OLLAMA_MODEL from config)

    Returns:
        LLM response dictionary or None if request fails
    """
    if model is None:
        model = OLLAMA_MODEL

    # Combine system and user prompts for Ollama
    combined_prompt = f"{system_prompt}\n\n{user_prompt}"

    data = {
        "model": model,
        "prompt": combined_prompt,
        "stream": False
    }
    
    logger.info("="*60)
    logger.info("[sendToLLMWithDynamicPrompt] SENDING REQUEST TO LLM")
    logger.info("="*60)
    logger.info(f"URL: {OLLAMA_URL}")
    logger.info(f"Model: {model}")
    logger.info(f"Prompt length: {len(combined_prompt)} chars")
    logger.info(f"--- PROMPT START ---")
    logger.info(combined_prompt)
    logger.info(f"--- PROMPT END ---")

    try:
        response = requests.post(OLLAMA_URL, json=data, timeout=OLLAMA_TIMEOUT_SECONDS)
        logger.info(f"Response Status: {response.status_code}")
        if response.status_code == 200:
            ollama_response = response.json()
            if 'response' in ollama_response:
                # Clean the response text from markdown code blocks
                response_text = strip_thinking_tags(ollama_response['response'])
                if response_text.startswith('```json'):
                    response_text = response_text[7:]
                    if response_text.endswith('```'):
                        response_text = response_text[:-3]
                elif response_text.startswith('```'):
                    response_text = response_text[3:]
                    if response_text.endswith('```'):
                        response_text = response_text[:-3]

                ollama_response['response'] = response_text.strip()
                ollama_response['metrics'] = build_ollama_metrics(
                    stage="cve_analysis",
                    model=model,
                    prompt_text=combined_prompt,
                    response_text=ollama_response['response'],
                    response_payload=ollama_response,
                )
                logger.info(f"--- LLM RESPONSE START ---")
                logger.info(ollama_response['response'])
                logger.info(f"--- LLM RESPONSE END ---")
                return ollama_response
            return ollama_response
        else:
            logger.error(f"Error: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        logger.error(f"Request failed: {e}")
        return None

def sendToLLM(content):
    data = {
        "model": OLLAMA_MODEL,
        "prompt": (
            "You are a security code reviewer for C files. "
            "Please analyze the following C file and identify potential vulnerabilities. "
            "Return the results in valid JSON format with EXACTLY these field names: "
            "'Type', 'Location', 'Severity', 'Explanation', and 'SuggestedFix'. "
            "Use this exact format:\n"
            "{\n"
            "  \"vulnerabilities\": [\n"
            "    {\n"
            "      \"Type\": \"vulnerability type\",\n"
            "      \"Location\": \"line number or function\",\n"
            "      \"Severity\": \"High/Medium/Low\",\n"
            "      \"Explanation\": \"detailed explanation\",\n"
            "      \"SuggestedFix\": \"how to fix it\"\n"
            "    }\n"
            "  ]\n"
            "}\n\n"
            f"{content}"
        ),
        "stream": False
    }

    logger.info("="*60)
    logger.info("[sendToLLM] SENDING REQUEST TO LLM")
    logger.info("="*60)
    logger.info(f"Prompt length: {len(data['prompt'])} chars")
    logger.info(f"--- PROMPT START ---")
    logger.info(data['prompt'])
    logger.info(f"--- PROMPT END ---")
    
    response = requests.post(OLLAMA_URL, json=data, timeout=OLLAMA_TIMEOUT_SECONDS)
    logger.info(f"Response Status: {response.status_code}")
    if response.status_code == 200:
        ollama_response = response.json()
        if 'response' in ollama_response:
            response_text = strip_thinking_tags(ollama_response['response'])
            if response_text.startswith('```json'):
                response_text = response_text[7:]
                if response_text.endswith('```'):
                    response_text = response_text[:-3]
            elif response_text.startswith('```'):
                response_text = response_text[3:]
                if response_text.endswith('```'):
                    response_text = response_text[:-3]

            ollama_response['response'] = response_text.strip()
            ollama_response['metrics'] = build_ollama_metrics(
                stage="file_analysis",
                model=OLLAMA_MODEL,
                prompt_text=data['prompt'],
                response_text=ollama_response['response'],
                response_payload=ollama_response,
            )
            logger.info(f"--- LLM RESPONSE START ---")
            logger.info(ollama_response['response'])
            logger.info(f"--- LLM RESPONSE END ---")
            return ollama_response
        return ollama_response
    else:
        logger.error(f"Error: {response.status_code}, {response.text}")
        return None
