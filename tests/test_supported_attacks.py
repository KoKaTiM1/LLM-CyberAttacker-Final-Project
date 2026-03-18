"""
Test Script: Validate Orchestrator Attack Type Filtering
=========================================================

This script tests that the system correctly:
1. ACCEPTS CVEs with Buffer Overflow (CWE-119 family) 
2. ACCEPTS CVEs with Format String (CWE-134)
3. REJECTS CVEs with unsupported vulnerability types (SQL Injection, XSS, etc.)
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.modules.orchestrator import PromptOrchestrator
from src.modules.cve_database import CVEDatabase
import json

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80)

def print_result(success, message):
    """Print colored result"""
    symbol = "✅" if success else "❌"
    print(f"{symbol} {message}")

def test_supported_cwe(orchestrator, cwe_id, cwe_name):
    """Test if CWE is correctly marked as supported"""
    print(f"\nTesting {cwe_id} ({cwe_name})...")
    is_supported = orchestrator.is_cwe_supported(cwe_id)
    
    if is_supported:
        print_result(True, f"{cwe_id} is SUPPORTED ✓")
        return True
    else:
        print_result(False, f"{cwe_id} should be supported but is NOT!")
        return False

def test_unsupported_cwe(orchestrator, cwe_id, cwe_name):
    """Test if CWE is correctly marked as unsupported"""
    print(f"\nTesting {cwe_id} ({cwe_name})...")
    is_supported = orchestrator.is_cwe_supported(cwe_id)
    
    if not is_supported:
        print_result(True, f"{cwe_id} is correctly REJECTED ✓")
        return True
    else:
        print_result(False, f"{cwe_id} should be rejected but is SUPPORTED!")
        return False

def test_cve_validation(orchestrator, db, cwe_id, should_pass):
    """Test CVE validation with real CVE data"""
    print(f"\nSearching for real CVE with {cwe_id}...")
    
    # Get a real CVE with this CWE
    cves = db.filter_by_cwe(cwe_id, limit=1)
    
    if not cves:
        print_result(False, f"No CVEs found with {cwe_id} in database")
        return False
    
    cve = cves[0]
    cve_id = cve.get('id') or cve.get('cve', {}).get('id', 'Unknown')
    print(f"Testing with: {cve_id}")
    
    # Validate
    is_supported, error_msg = orchestrator.validate_cve_support(cve)
    
    if should_pass:
        if is_supported:
            print_result(True, f"CVE {cve_id} passed validation ✓")
            return True
        else:
            print_result(False, f"CVE {cve_id} should pass but was REJECTED!")
            print(f"Error message: {error_msg}")
            return False
    else:
        if not is_supported:
            print_result(True, f"CVE {cve_id} correctly REJECTED ✓")
            print(f"Rejection reason: {error_msg[:100]}...")
            return True
        else:
            print_result(False, f"CVE {cve_id} should be rejected but PASSED!")
            return False

def main():
    print_header("ORCHESTRATOR ATTACK TYPE VALIDATION TEST")
    
    # Initialize
    print("\n🔧 Initializing Orchestrator and CVE Database...")
    orchestrator = PromptOrchestrator()
    db = CVEDatabase()
    
    supported_list = orchestrator.get_supported_cwe_list()
    print(f"📋 Supported CWE types: {', '.join(supported_list)}")
    
    results = []
    
    # ========== TEST 1: Buffer Overflow Family (SHOULD PASS) ==========
    print_header("TEST 1: Buffer Overflow Family (Should be SUPPORTED)")
    
    tests = [
        ("CWE-119", "Buffer Overflow"),
        ("CWE-120", "Buffer Copy without Checking Size"),
        ("CWE-121", "Stack-based Buffer Overflow"),
        ("CWE-122", "Heap-based Buffer Overflow"),
        ("CWE-125", "Out-of-bounds Read"),
        ("CWE-787", "Out-of-bounds Write"),
    ]
    
    for cwe_id, cwe_name in tests:
        results.append(test_supported_cwe(orchestrator, cwe_id, cwe_name))
    
    # Test with real CVE
    print("\n📝 Testing with REAL CVE data (Buffer Overflow)...")
    results.append(test_cve_validation(orchestrator, db, "CWE-119", should_pass=True))
    
    # ========== TEST 2: Format String (SHOULD PASS) ==========
    print_header("TEST 2: Format String (Should be SUPPORTED)")
    
    results.append(test_supported_cwe(orchestrator, "CWE-134", "Format String"))
    
    # Test with real CVE
    print("\n📝 Testing with REAL CVE data (Format String)...")
    results.append(test_cve_validation(orchestrator, db, "CWE-134", should_pass=True))
    
    # ========== TEST 3: Unsupported Types (SHOULD FAIL) ==========
    print_header("TEST 3: Unsupported Attack Types (Should be REJECTED)")
    
    unsupported_tests = [
        ("CWE-89", "SQL Injection"),
        ("CWE-79", "Cross-site Scripting (XSS)"),
        ("CWE-77", "Command Injection"),
        ("CWE-78", "OS Command Injection"),
        ("CWE-416", "Use After Free"),
        ("CWE-190", "Integer Overflow"),
    ]
    
    for cwe_id, cwe_name in unsupported_tests:
        results.append(test_unsupported_cwe(orchestrator, cwe_id, cwe_name))
    
    # Test with real CVE (SQL Injection)
    print("\n📝 Testing with REAL CVE data (SQL Injection - should be REJECTED)...")
    results.append(test_cve_validation(orchestrator, db, "CWE-89", should_pass=False))
    
    # ========== SUMMARY ==========
    print_header("TEST SUMMARY")
    
    total = len(results)
    passed = sum(results)
    failed = total - passed
    
    print(f"\n📊 Results:")
    print(f"   Total Tests:  {total}")
    print(f"   Passed:       {passed} ✅")
    print(f"   Failed:       {failed} ❌")
    print(f"   Success Rate: {(passed/total*100):.1f}%")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! System is correctly filtering attack types.")
        return 0
    else:
        print(f"\n⚠️ {failed} TESTS FAILED! Please review the orchestrator configuration.")
        return 1

if __name__ == "__main__":
    exit(main())
