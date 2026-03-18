"""
Demo: File-Based Vulnerability Analysis
========================================

This demo shows how to use the system with a FILE as input.
The system will:
1. Analyze the file to identify vulnerability type
2. Generate appropriate exploit script
3. Execute in sandbox

NO CVE ID NEEDED - Just provide a file path!
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from modules.cyber_attack_graph import run_cyber_attack


def demo_file_input():
    """Demonstrate file-based vulnerability analysis"""
    
    print("=" * 80)
    print("FILE-BASED VULNERABILITY ANALYSIS DEMO")
    print("=" * 80)
    print()
    
    # Path to vulnerable file
    vulnerable_file = project_root / "demos" / "vulnerable_example.c"
    
    if not vulnerable_file.exists():
        print(f"❌ Error: File not found: {vulnerable_file}")
        return
    
    print(f"📁 Target File: {vulnerable_file}")
    print(f"📊 File Size: {vulnerable_file.stat().st_size} bytes")
    print()
    print("=" * 80)
    print("STARTING WORKFLOW...")
    print("=" * 80)
    print()
    
    # Method 1: Using user_input (automatic detection)
    print("🚀 Method 1: Auto-detection from user_input")
    result = run_cyber_attack(user_input=str(vulnerable_file))
    
    # Or Method 2: Explicit file_path parameter
    # print("🚀 Method 2: Explicit file_path parameter")
    # result = run_cyber_attack(file_path=str(vulnerable_file))
    
    print()
    print("=" * 80)
    print("WORKFLOW RESULTS")
    print("=" * 80)
    print()
    
    print(f"Input Type: {result.get('input_type')}")
    print(f"Final State: {result.get('current_state')}")
    
    if result.get('error_message'):
        print(f"❌ Error: {result.get('error_message')}")
    else:
        print("✅ Success!")
        
        if result.get('cwe_id'):
            print(f"🔍 Identified CWE: {result['cwe_id']}")
        
        if result.get('vulnerability_data'):
            vuln = result['vulnerability_data']
            if 'vulnerabilities' in vuln and len(vuln['vulnerabilities']) > 0:
                v = vuln['vulnerabilities'][0]
                print(f"🎯 Vulnerability Type: {v.get('Type')}")
                print(f"📍 Location: {v.get('Location')}")
                print(f"📝 Explanation: {v.get('Explanation', '')[:200]}...")
        
        if result.get('attack_script'):
            script_lines = result['attack_script'].count('\n')
            script_chars = len(result['attack_script'])
            print(f"📜 Exploit Script: {script_lines} lines, {script_chars} characters")
        
        if result.get('sandbox_result'):
            print(f"🏖️ Sandbox Execution: Completed")
    
    print()
    print("=" * 80)
    print("EXECUTION LOG")
    print("=" * 80)
    
    for log_entry in result.get('execution_log', []):
        print(log_entry)
    
    print()
    print("=" * 80)
    print("DEMO COMPLETED")
    print("=" * 80)


if __name__ == "__main__":
    demo_file_input()
