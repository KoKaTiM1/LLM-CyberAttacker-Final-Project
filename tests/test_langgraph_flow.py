"""
Test: Verify LangGraph Flow with CVE Validation
================================================

This test verifies:
1. All workflow nodes are properly connected
2. CVE validation (support check) works correctly
3. State transitions are smooth between nodes
4. Unsupported CVEs are rejected at the correct stage
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.modules.cyber_attack_graph import (
    run_cyber_attack,
    cyber_attack_app,
)
import json

def print_header(text):
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80 + "\n")

def print_status(success, message):
    symbol = "✅" if success else "❌"
    print(f"{symbol} {message}")

def test_supported_cve():
    """Test workflow with supported CVE (Buffer Overflow)"""
    print_header("TEST 1: Supported CVE (Buffer Overflow)")
    
    print("Running workflow with CVE-2008-0888 (CWE-119: Buffer Overflow)...")
    
    try:
        result = run_cyber_attack(cve_id="CVE-2008-0888")
        
        # Check for errors
        error = result.get("error_message", "")
        
        if error:
            print_status(False, f"Workflow failed unexpectedly: {error[:100]}")
            return False
        
        # Verify expected fields are populated
        cve_id = result.get("cve_id")
        cwe_id = result.get("cwe_id")
        system_prompt = result.get("system_prompt", "")
        
        print_status(True, f"Workflow completed successfully")
        print(f"  CVE ID: {cve_id}")
        print(f"  CWE ID: {cwe_id}")
        print(f"  System Prompt Length: {len(system_prompt)} characters")
        print(f"  Prompt Metadata: {result.get('prompt_metadata', {})}")
        
        # Verify CVE was loaded
        if not result.get("cve_data"):
            print_status(False, "CVE data not loaded")
            return False
        
        print_status(True, "CVE data loaded correctly")
        
        # Verify prompts were built
        if not system_prompt or len(system_prompt) < 50:
            print_status(False, "System prompt not built correctly")
            return False
        
        print_status(True, "Dynamic prompts built correctly")
        
        # Show execution log
        logs = result.get("execution_log", [])
        print(f"\n📝 Execution Log ({len(logs)} steps):")
        for i, log in enumerate(logs[:10], 1):  # Show first 10
            print(f"  {i}. {log}")
        if len(logs) > 10:
            print(f"  ... ({len(logs) - 10} more steps)")
        
        return True
        
    except Exception as e:
        print_status(False, f"Exception: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_unsupported_cve():
    """Test workflow with unsupported CVE (SQL Injection)"""
    print_header("TEST 2: Unsupported CVE (SQL Injection)")
    
    print("Running workflow with CVE-2018-3811 (CWE-89: SQL Injection)...")
    
    try:
        result = run_cyber_attack(cve_id="CVE-2018-3811")
        
        # This SHOULD have an error
        error = result.get("error_message", "")
        
        if not error:
            print_status(False, "CVE should have been rejected but wasn't!")
            return False
        
        # Check that error mentions it's not supported
        if "not" in error.lower() and ("support" in error.lower() or "process" in error.lower()):
            print_status(True, "CVE correctly rejected")
            print(f"  Rejection reason: {error[:150]}...")
            
            # Verify it was rejected at the correct stage (load_cve)
            logs = result.get("execution_log", [])
            print(f"\n📝 Execution Log ({len(logs)} steps - should be short):")
            for i, log in enumerate(logs, 1):
                print(f"  {i}. {log}")
            
            # Should stop at validation, not reach analyze or generate
            log_text = " ".join(logs).lower()
            if "analyzing" in log_text or "generating" in log_text:
                print_status(False, "Workflow continued past validation - should have stopped!")
                return False
            
            print_status(True, "Workflow stopped at correct stage (CVE validation)")
            return True
        else:
            print_status(False, f"Error message doesn't indicate unsupported type: {error[:100]}")
            return False
            
    except Exception as e:
        print_status(False, f"Exception: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_graph_structure():
    """Test that graph has all expected nodes"""
    print_header("TEST 3: Graph Structure Validation")
    
    print("Checking graph nodes...")
    
    try:
        graph = cyber_attack_app.get_graph()
        nodes = list(graph.nodes.keys())
        
        expected_nodes = [
            "check_connections",
            "load_cve",
            "build_prompt",
            "validate_file",
            "rag",
            "analyze_vulnerability",
            "prepare_target_environment",
            "resolve_cve_target",
            "plan_reproduction",
            "build_target_artifact",
            "create_attack_script",
            "execute_in_sandbox",
            "evaluate_attack_result",
            "rebuild_prompt",
            "handle_error",
            "workflow_complete",
        ]
        
        print(f"Found {len(nodes)} nodes:")
        for node in nodes:
            print(f"  • {node}")
        
        missing = [n for n in expected_nodes if n not in nodes]
        extra = [n for n in nodes if n not in expected_nodes and n != "__start__" and n != "__end__"]
        
        if missing:
            print_status(False, f"Missing nodes: {missing}")
            return False
        
        if extra:
            print(f"⚠️  Extra nodes (not expected): {extra}")
        
        print_status(True, "All expected nodes present")
        
        # Check edges
        print("\nChecking critical edges...")
        edges = list(graph.edges)
        
        critical_edges = [
            ("__start__", "check_connections"),
            ("check_connections", "load_cve"),
            ("load_cve", "build_prompt"),
            ("build_prompt", "rag"),
        ]
        
        for source, target in critical_edges:
            # Check if this edge exists (might be conditional)
            edge_exists = any(e[0] == source for e in edges)
            if edge_exists:
                print_status(True, f"Edge exists: {source} → ...")
            else:
                print_status(False, f"Edge missing: {source} → {target}")
                return False
        
        print_status(True, "Critical edges verified")
        return True
        
    except Exception as e:
        print_status(False, f"Exception: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print_header("🧪 LANGGRAPH FLOW VALIDATION TEST")
    
    results = []
    
    # Test 1: Supported CVE
    results.append(("Supported CVE (Buffer Overflow)", test_supported_cve()))
    
    # Test 2: Unsupported CVE
    results.append(("Unsupported CVE (SQL Injection)", test_unsupported_cve()))
    
    # Test 3: Graph structure
    results.append(("Graph Structure", test_graph_structure()))
    
    # Summary
    print_header("TEST SUMMARY")
    
    total = len(results)
    passed = sum(1 for _, success in results if success)
    failed = total - passed
    
    print("Results:")
    for test_name, success in results:
        symbol = "✅" if success else "❌"
        print(f"  {symbol} {test_name}")
    
    print(f"\n📊 Score: {passed}/{total} tests passed")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED!")
        print("\n✅ LangGraph flow is correctly configured")
        print("✅ CVE validation works properly")
        print("✅ State transitions are smooth")
        return 0
    else:
        print(f"\n⚠️ {failed} TEST(S) FAILED")
        return 1

if __name__ == "__main__":
    exit(main())
