import json
import requests
import re
import logging
from .model_config import OLLAMA_MODEL, OLLAMA_URL, OLLAMA_TIMEOUT_SECONDS
from .prompt_builder import build_exploit_prompt
from .llm_utils import strip_thinking_tags

logger = logging.getLogger(__name__)


def extract_code_from_markdown(text: str) -> str:
    """
    Extract Python code from markdown-formatted text.
    Looks for code blocks enclosed in ```python ... ``` or ``` ... ```
    
    Args:
        text: The markdown text containing code blocks
        
    Returns:
        Extracted Python code, or the original text if no code block found
    """
    # Try to find Python code blocks
    python_code_pattern = r'```python\s*\n(.*?)```'
    matches = re.findall(python_code_pattern, text, re.DOTALL)
    
    if matches:
        # Return the first Python code block found
        return matches[0].strip()
    
    # Try generic code blocks
    generic_code_pattern = r'```\s*\n(.*?)```'
    matches = re.findall(generic_code_pattern, text, re.DOTALL)
    
    if matches:
        # Return the first code block found
        return matches[0].strip()
    
    # If no code block found, return original text
    return text


def generateExploitWithDynamicPrompt(vulnerability_data: dict, system_prompt: str, user_prompt: str):
    """
    Generate exploit script using dynamic prompts from Orchestrator.
    This is the new approach that uses context-aware, expert-specific prompts.
    
    Args:
        vulnerability_data: Dictionary with vulnerability details
        system_prompt: Expert profile prompt from Orchestrator
        user_prompt: Task-specific prompt from Orchestrator
        
    Returns:
        Generated exploit code or None if generation fails
    """
    task_prompt = f"{user_prompt}\n\n"
    task_prompt += "## Vulnerability Details\n"
    task_prompt += f"Type: {vulnerability_data.get('Type', 'Unknown')}\n"
    task_prompt += f"Location: {vulnerability_data.get('Location', 'Unknown')}\n"
    task_prompt += f"Explanation: {vulnerability_data.get('Explanation', 'Unknown')}\n"
    task_prompt += "\nGenerate the exploit code now:"

    payload = {
        "model": OLLAMA_MODEL,
        "system": system_prompt,
        "prompt": task_prompt,
        "stream": False
    }

    logger.info("="*60)
    logger.info("[generateExploitWithDynamicPrompt] SENDING REQUEST TO LLM")
    logger.info("="*60)
    logger.info(f"URL: {OLLAMA_URL}")
    logger.info(f"Model: {OLLAMA_MODEL}")
    logger.info(f"System prompt length: {len(system_prompt)} chars")
    logger.info(f"Task prompt length: {len(task_prompt)} chars")
    logger.info(f"--- SYSTEM PROMPT START ---")
    logger.info(system_prompt)
    logger.info(f"--- SYSTEM PROMPT END ---")
    logger.info(f"--- TASK PROMPT START ---")
    logger.info(task_prompt)
    logger.info(f"--- TASK PROMPT END ---")
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT_SECONDS)
        logger.info(f"Response Status: {response.status_code}")

        if response.status_code == 200:
            response_data = response.json()
            if isinstance(response_data, dict) and 'response' in response_data:
                llm_response = strip_thinking_tags(response_data['response'])
                logger.info(f"--- LLM RAW RESPONSE START ---")
                logger.info(llm_response)
                logger.info(f"--- LLM RAW RESPONSE END ---")
                extracted = extract_code_from_markdown(llm_response)
                logger.info(f"--- EXTRACTED CODE START ({len(extracted)} chars) ---")
                logger.info(extracted)
                logger.info(f"--- EXTRACTED CODE END ---")
                return extracted
            return response_data
        else:
            logger.error(f"Error: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        logger.error(f"Request failed: {e}")
        return None


def resultsFromLLM(LLMresult):
    try:
        data = json.loads(LLMresult)
        
        # Handle structured JSON with vulnerabilities array
        if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
            vulnerability = data['vulnerabilities'][0]
        else:
            print("No vulnerabilities found in JSON")
            return None
            
        # Use standardized field names (Type, Location, Explanation)
        if not vulnerability.get("Type") or not vulnerability.get("Location") or not vulnerability.get("Explanation"):
            print("Json file from LLM is missing details")
            return None
            
        prompt = build_exploit_prompt(vulnerability)
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        }

        logger.info("="*60)
        logger.info("[resultsFromLLM] SENDING REQUEST TO LLM")
        logger.info("="*60)
        logger.info(f"Prompt length: {len(prompt)} chars")
        logger.info(f"--- PROMPT START ---")
        logger.info(prompt)
        logger.info(f"--- PROMPT END ---")

        response = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT_SECONDS)
        logger.info(f"Response Status: {response.status_code}")
        if response.status_code == 200:
            response_data = response.json()
            if isinstance(response_data, dict) and 'response' in response_data:
                llm_response = strip_thinking_tags(response_data['response'])
                logger.info(f"--- LLM RAW RESPONSE START ---")
                logger.info(llm_response)
                logger.info(f"--- LLM RAW RESPONSE END ---")
                extracted = extract_code_from_markdown(llm_response)
                logger.info(f"--- EXTRACTED CODE START ({len(extracted)} chars) ---")
                logger.info(extracted)
                logger.info(f"--- EXTRACTED CODE END ---")
                return extracted
            return response_data
        else:
            logger.error(f"Error: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"Request failed: {e}")
        return None
