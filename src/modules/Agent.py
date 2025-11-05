import json
import requests

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
            
        url = "http://localhost:11434/api/generate"
        prompt = (
            "You are a university cybersecurity professor creating simple educational C code demonstrations. "
            "A student has found this vulnerability:\n\n"
            f"Vulnerability Type: {vulnerability['Type']}\n"
            f"Found at: {vulnerability['Location']}\n"
            f"Details: {vulnerability['Explanation']}\n\n"
            "Create a simple C program (not Python) that demonstrates this vulnerability:\n"
            "1. Use basic C functions like sprintf, strcpy, gets, etc.\n"
            "2. Keep it simple - small buffers (20-50 bytes), clear overflow\n"
            "3. Add printf statements to show before/after states\n"
            "4. Show actual memory corruption when compiled and run\n"
            "5. Include comments explaining what happens\n\n"
            "IMPORTANT OUTPUT FORMAT REQUIREMENTS:\n"
            "- Output ONLY pure C source code\n"
            "- NO markdown formatting (no ```c, no ```, no **bold**, no # headers)\n"
            "- NO explanatory text before or after the code\n"
            "- NO Unicode characters or special symbols\n"
            "- Start directly with #include statements\n"
            "- End with the closing brace of main() function\n"
            "- The file must be in pure C format that can compile directly "
            "with gcc\n\n"
            "Make it a complete, compilable C program with #include "
            "statements and main() function. "
            "This should actually demonstrate the real vulnerability when "
            "compiled with gcc and run. "
            "Keep it educational and simple - no complex exploits, just show "
            "the basic overflow behavior."
        )
        payload = {
            "model": "gpt-oss:20b",
            "prompt": prompt,
            "stream": False
        }
        response = requests.post(url, json=payload, timeout=60000)
        print(f"Exploit Generation Response Status: {response.status_code}")
        if response.status_code == 200:
            print(f"Exploit Generation Response: {response.json()}")
            return response.json()
        else:
            print(f"Error: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"Request failed: {e}")
        return None
'''
def resultsFromLLM(LLMresult):
    API_KEY = ""
    url = ""
    data = json.loads(LLMresult)
    if not data["Type"] or not data["Location"] or not data["Explanation"]:
        print("Json file from LLM is missing details")
        return
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }

    payload = {
        "model": "oss-20b",
        "messages": [
            {"role": "system", "content": "You are an expert exploit developer."},
            {"role": "user", "content": f"""Here is a vulnerability that was found in a C file:

    Type: {data["Type"]}
    Location: {data["Location"]}
    Explanation: {data["Explanation"]}

    Please generate a Python proof-of-concept exploit script that demonstrates how this vulnerability can be exploited.
    The script should be runnable and include necessary comments."""}
        ]
    }
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        if response.status_code == 200:
            process_vulnerability_and_attack(LLMresult)

        else:
            print(f"Error: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"Request failed: {e}")
        return None
        return response.json()
'''
