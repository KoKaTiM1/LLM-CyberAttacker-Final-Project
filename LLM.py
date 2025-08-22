from pathlib import Path
import requests
def init():
    check1 = checkAPIconnectionWithLLM()
    check2 = checkAPIconnectionWithAgent()
    if check1 and check2:
        file_path_input = input("please enter full path to file: ").strip().strip('"')
        file_path = Path(file_path_input)
        content = getFile(file_path)
        if content is not None:
            print("file loaded OK")
            getFile(file_path)
    else:
        if check1 and check2:
            print("Both API's lost connection")
        elif check1 is False:
            print("LLM API connection lost")
        elif check2 is False:
            print("Agent API connection lost")


def getFile(path: Path):
    if not path.exists() or not path.is_file():
        print("file not found")
        return None

    if path.suffix.lower() != ".c":
        print("this is not C file")
        return None

    try:
        fileContent = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"failed to read file: {e}")
        return None

    if len(fileContent.strip()) == 0:
        print("empty file")
        return None
    sendToLLM(fileContent)


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
            #TODO send to Agent
            pass
        else:
            print(f"Error: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"Request failed: {e}")
        return None
