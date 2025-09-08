from pathlib import Path
from urllib import response
import requests
from Agent import resultsFromLLM
   


def getFile(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        print("file not found")
        return False

    if path.suffix.lower() != ".c":
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


def checkAPIconnectionWithLLM() -> bool:
    url = ""
    response = requests.get(url,timeout=5)
    if response.status_code == 200:
        return True
    else: return False

def checkAPIconnectionWithAgent() -> bool:
    url = ""
    response = requests.get(url,timeout=5)
    if response.status_code == 200:
        return True
    else:
        return False

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
