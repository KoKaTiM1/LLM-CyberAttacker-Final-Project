import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.LLM import _clean_structured_response
from modules.agent_langgraph_wrapper import _parse_llm_vulnerability_json


def test_clean_structured_response_removes_json_fences():
    response = """```json
{"vulnerabilities":[{"Type":"buffer overflow"}]}
```"""

    cleaned = _clean_structured_response(response)

    assert cleaned == '{"vulnerabilities":[{"Type":"buffer overflow"}]}'


def test_parse_llm_vulnerability_json_extracts_json_from_wrapped_text():
    response = """Here is the analysis:

```json
{
  "vulnerabilities": [
    {
      "Type": "buffer overflow",
      "Location": "main",
      "Severity": "High",
      "Explanation": "Unsafe copy into fixed-size buffer.",
      "SuggestedFix": "Use bounds-checked copy."
    }
  ]
}
```"""

    parsed = _parse_llm_vulnerability_json(response)

    assert parsed["vulnerabilities"][0]["Type"] == "buffer overflow"
    assert parsed["vulnerabilities"][0]["Location"] == "main"


def test_parse_llm_vulnerability_json_recovers_from_bare_field_text():
    response = """
Type: not useful
{
  "Type": "heap overflow",
  "Location": "parse_file",
  "Severity": "High",
  "Explanation": "Attacker controls length field.
Second line in same string.",
  "SuggestedFix": "Validate length before allocation."
}
"""

    parsed = _parse_llm_vulnerability_json(response)

    vuln = parsed["vulnerabilities"][0]
    assert vuln["Type"] == "heap overflow"
    assert "Second line" in vuln["Explanation"]
