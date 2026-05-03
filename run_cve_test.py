"""Quick test: run full CVE mode execution"""
import logging
import sys

# Send ALL logs to stdout (not stderr) so PowerShell doesn't show them in red
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    stream=sys.stdout,
)

from src.modules.cyber_attack_graph import run_cyber_attack

result = run_cyber_attack(cve_id="CVE-2008-0888")

print("\n" + "=" * 80)
print("FINAL RESULT:")
print("=" * 80)
print(f"Current State: {result.get('current_state')}")
print(f"Error: {result.get('error_message') or 'None'}")
print(f"Attack Script Length: {len(result.get('attack_script', ''))} chars")
print(f"Input Type: {result.get('input_type')}")
print(f"CVE ID: {result.get('cve_id')}")
print(f"CWE ID: {result.get('cwe_id')}")

print("\nExecution Log:")
for log in result.get("execution_log", []):
    print(f"  {log}")

if result.get("attack_script"):
    print("\n" + "=" * 80)
    print("GENERATED EXPLOIT SCRIPT:")
    print("=" * 80)
    print(result["attack_script"][:2000])
