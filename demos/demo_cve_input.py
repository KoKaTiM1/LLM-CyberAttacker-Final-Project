"""
Demo: CVE-Based Vulnerability Analysis
=======================================

This demo shows how to use the system with a CVE ID as input.
The system will:
1. Load CVE from database
2. Validate it's a supported type (Buffer Overflow or Format String)
3. Build dynamic prompts
4. Generate exploit script
5. Execute in sandbox

Just provide a CVE ID!
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from modules.cyber_attack_graph import run_cyber_attack


def demo_cve_input():
    """Demonstrate CVE-based vulnerability analysis"""
    
    print("=" * 80)
    print("CVE-BASED VULNERABILITY ANALYSIS DEMO")
    print("=" * 80)
    print()
    
    # Example CVE IDs (Buffer Overflow)
    cve_examples = [
        "CVE-2008-0888",  # Buffer Overflow
        "CVE-2007-4060",  # Format String
    ]
    
    cve_id = cve_examples[0]  # Change index to test different CVEs
    
    print(f"🔍 Target CVE: {cve_id}")
    print()
    print("=" * 80)
    print("STARTING WORKFLOW...")
    print("=" * 80)
    print()
    
    # Method 1: Using user_input (automatic detection)
    print("🚀 Method 1: Auto-detection from user_input")
    result = run_cyber_attack(user_input=cve_id)
    
    # Or Method 2: Explicit cve_id parameter
    # print("🚀 Method 2: Explicit cve_id parameter")
    # result = run_cyber_attack(cve_id=cve_id)
    
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
        
        if result.get('cve_data'):
            cve_data = result['cve_data']
            print(f"📋 CVE Description: {cve_data.get('description', '')[:200]}...")
        
        if result.get('cwe_id'):
            print(f"🔍 CWE: {result['cwe_id']}")
        
        if result.get('prompt_metadata'):
            meta = result['prompt_metadata']
            print(f"👤 Expert Profile: {meta.get('expert_profile')}")
            print(f"📚 Methodology: {meta.get('methodology_file')}")
        
        if result.get('vulnerability_data'):
            vuln = result['vulnerability_data']
            if 'vulnerabilities' in vuln and len(vuln['vulnerabilities']) > 0:
                v = vuln['vulnerabilities'][0]
                print(f"🎯 Vulnerability Type: {v.get('Type')}")
                print(f"📍 Location: {v.get('Location')}")
        
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
    demo_cve_input()
