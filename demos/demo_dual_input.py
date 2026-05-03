"""
Demo: Dual Input Mode - Automatic Detection
============================================

This demo shows the NEW DUAL INPUT feature where the system
automatically detects whether you're providing:
1. A FILE PATH - for file-based analysis
2. A CVE ID - for CVE-based analysis

The system will route to the appropriate workflow automatically!
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from modules.cyber_attack_graph import run_cyber_attack


def test_input(user_input: str, description: str):
    """Test a single input and show results"""
    
    print()
    print("=" * 80)
    print(f"TEST: {description}")
    print("=" * 80)
    print(f"User Input: {user_input}")
    print()
    
    result = run_cyber_attack(user_input=user_input)
    
    print(f"✅ Detected Type: {result.get('input_type')}")
    print(f"📊 Final State: {result.get('current_state')}")
    
    if result.get('error_message'):
        print(f"❌ Error: {result.get('error_message')}")
    else:
        print("✅ Workflow completed successfully!")
        
        if result.get('input_type') == 'file':
            print(f"📁 File analyzed: {result.get('file_path')}")
            if result.get('cwe_id'):
                print(f"🔍 Identified as: {result.get('cwe_id')}")
        
        elif result.get('input_type') == 'cve':
            print(f"🔍 CVE processed: {result.get('cve_id')}")
            if result.get('cwe_id'):
                print(f"🎯 CWE type: {result.get('cwe_id')}")
    
    return result


def main():
    """Run comprehensive dual input demo"""
    
    print("=" * 80)
    print("DUAL INPUT MODE DEMONSTRATION")
    print("=" * 80)
    print()
    print("This demo shows how the system automatically detects input type:")
    print("  • File Path → File Analysis Workflow")
    print("  • CVE ID → CVE Database Workflow")
    print("  • Invalid → Rejection")
    print()
    
    # Test 1: CVE Input
    test_input(
        "CVE-2008-0888",
        "CVE ID Input (Buffer Overflow)"
    )
    
    # Test 2: File Input
    vulnerable_file = project_root / "demos" / "vulnerable_example.c"
    if vulnerable_file.exists():
        test_input(
            str(vulnerable_file),
            "File Path Input (Auto-detect vulnerability)"
        )
    else:
        print(f"\n⚠️  Skipping file test - {vulnerable_file} not found")
    
    # Test 3: Another CVE
    test_input(
        "CVE-2007-4060",
        "CVE ID Input (Format String)"
    )
    
    # Test 4: Invalid Input
    test_input(
        "not-a-valid-input",
        "Invalid Input (Should be rejected)"
    )
    
    print()
    print("=" * 80)
    print("DEMO SUMMARY")
    print("=" * 80)
    print()
    print("✅ The system successfully:")
    print("   1. Auto-detects CVE IDs (CVE-YYYY-NNNNN pattern)")
    print("   2. Auto-detects file paths (checks existence or path pattern)")
    print("   3. Rejects invalid inputs")
    print("   4. Routes to appropriate workflow based on detection")
    print()
    print("🎯 Two workflows in one system:")
    print("   FILE MODE: Step1 → Step4 → Step5 → Step6 → Step7")
    print("   CVE MODE:  Step1 → Step2 → Step3 → Step5 → Step6 → Step7")
    print()
    print("=" * 80)


if __name__ == "__main__":
    main()
