"""
Test: Input Type Detection
===========================

Quick test to verify the detect_input_type function works correctly.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from modules.agent_langgraph_wrapper import detect_input_type


def test_detection():
    """Test various input types"""
    
    test_cases = [
        # (input, expected_type, description)
        ("CVE-2008-0888", "cve", "Standard CVE ID"),
        ("CVE-2024-12345", "cve", "Recent CVE ID"),
        ("cve-2020-1234", "cve", "Lowercase CVE ID"),
        ("src/vulnerable.c", "file", "Relative file path with /"),
        ("C:\\Users\\test\\file.c", "file", "Windows absolute path"),
        ("/home/user/file.c", "file", "Linux absolute path"),
        ("vulnerable_example.c", "file", "Filename with extension"),
        ("some random text", "invalid", "Plain text"),
        ("not-a-cve", "invalid", "Dash but not CVE format"),
        ("CVE-20-123", "invalid", "Wrong CVE year format"),
    ]
    
    print("=" * 80)
    print("INPUT TYPE DETECTION TESTS")
    print("=" * 80)
    print()
    
    passed = 0
    failed = 0
    
    for input_str, expected_type, description in test_cases:
        detected_type, value = detect_input_type(input_str)
        
        status = "✅" if detected_type == expected_type else "❌"
        if detected_type == expected_type:
            passed += 1
        else:
            failed += 1
        
        print(f"{status} {description}")
        print(f"   Input: '{input_str}'")
        print(f"   Expected: {expected_type}")
        print(f"   Detected: {detected_type}")
        if value != input_str.strip():
            print(f"   Value: '{value}'")
        print()
    
    print("=" * 80)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 80)
    
    return failed == 0


if __name__ == "__main__":
    success = test_detection()
    sys.exit(0 if success else 1)
