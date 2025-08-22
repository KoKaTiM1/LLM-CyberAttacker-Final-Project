import json
import requests
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
            #TODO send to factory
            pass
        else:
            print(f"Error: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"Request failed: {e}")
        return None


