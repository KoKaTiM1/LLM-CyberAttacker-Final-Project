from pathlib import Path
from urllib import response
import requests
from .Agent import resultsFromLLM


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
        url = "http://localhost:11434/api/generate"
        data = {
            "model": "gpt-oss:20b",
            "prompt": "ping",
            "stream": False
        }
        try:
            response = requests.post(url, json=data, timeout=60000)
            if response.status_code == 200:
                print("Connected to gpt-oss:20b via Ollama.")
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
def sendToLLM(content):
    url = "http://localhost:11434/api/generate"
    data = {
        "model": "gpt-oss:20b",
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

    response = requests.post(url, json=data, timeout=60000)
    if response.status_code == 200:
        ollama_response = response.json()
        if 'response' in ollama_response:
            # Clean the response text from markdown code blocks
            response_text = ollama_response['response'].strip()
            if response_text.startswith('```json'):
                response_text = response_text[7:]  # Remove ```json
                if response_text.endswith('```'):
                    response_text = response_text[:-3]  # Remove ```
            elif response_text.startswith('```'):
                response_text = response_text[3:]  # Remove ```
                if response_text.endswith('```'):
                    response_text = response_text[:-3]  # Remove ```
            
            # Return cleaned response in Ollama format
            ollama_response['response'] = response_text.strip()
            return ollama_response
        return ollama_response
    else:
        print(f"Error: {response.status_code}, {response.text}")
        return None

"""
def sendToLLM(content):
    API_KEY = ""
    url = ""

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }

    data = {
        "model": "oss-20b",
        "messages": [
            {"role": "system", "content": "You are a security code reviewer for C files."},
            {"role": "user", "content": f"Please analyze the following C file and identify potential vulnerabilities. "
                                        f"Return the results in valid JSON format, including vulnerability type, "
                                        f"location (line or function), severity, explanation, and suggested fix:\n\n{content}"}
        ]
    }

    try:
        response = requests.post(url, headers=headers, json=data, timeout=15)
        if response.status_code == 200:
            resultsFromLLM(response.json())
            pass
        else:
            print(f"Error: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"Request failed: {e}")
        return None
    return response.json()
"""