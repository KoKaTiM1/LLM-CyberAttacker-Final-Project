"""
Quick Integration Test - No LLM Required
=========================================

This test verifies the workflow structure WITHOUT calling the actual LLM.
It uses mock data to verify routing and state transitions.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

def test_file_mode_routing():
    """Test that FILE mode follows the correct path"""
    print("\n" + "=" * 80)
    print("TEST 1: FILE MODE ROUTING")
    print("=" * 80)
    
    from modules.agent_langgraph_wrapper import AgentContext, WorkflowState
    
    # Create FILE mode context
    file_path = project_root / "demos" / "vulnerable_example.c"
    ctx = AgentContext(user_input=str(file_path))
    
    print(f"✅ Created context with file: {file_path}")
    print(f"   Input type detected: {ctx.input_type}")
    
    assert ctx.input_type == "file", f"Expected 'file', got '{ctx.input_type}'"
    assert ctx.file_path is not None, "File path should be set"
    assert ctx.cve_id is None, "CVE ID should be None in file mode"
    
    print("✅ File mode context created correctly")
    print()
    return True


def test_cve_mode_routing():
    """Test that CVE mode follows the correct path"""
    print("\n" + "=" * 80)
    print("TEST 2: CVE MODE ROUTING")
    print("=" * 80)
    
    from modules.agent_langgraph_wrapper import AgentContext, WorkflowState
    
    # Create CVE mode context
    ctx = AgentContext(user_input="CVE-2008-0888")
    
    print(f"✅ Created context with CVE: CVE-2008-0888")
    print(f"   Input type detected: {ctx.input_type}")
    
    assert ctx.input_type == "cve", f"Expected 'cve', got '{ctx.input_type}'"
    assert ctx.cve_id == "CVE-2008-0888", f"Expected 'CVE-2008-0888', got '{ctx.cve_id}'"
    assert ctx.file_path is None, "File path should be None in CVE mode"
    
    print("✅ CVE mode context created correctly")
    print()
    return True


def test_invalid_input_rejection():
    """Test that invalid input is rejected"""
    print("\n" + "=" * 80)
    print("TEST 3: INVALID INPUT REJECTION")
    print("=" * 80)
    
    from modules.agent_langgraph_wrapper import AgentContext, WorkflowState
    
    # Create invalid input context
    ctx = AgentContext(user_input="this is not valid")
    
    print(f"✅ Created context with invalid input")
    print(f"   Input type detected: {ctx.input_type}")
    
    assert ctx.input_type == "invalid", f"Expected 'invalid', got '{ctx.input_type}'"
    
    print("✅ Invalid input correctly identified")
    print()
    return True


def test_graph_state_conversion():
    """Test that state conversion works correctly"""
    print("\n" + "=" * 80)
    print("TEST 4: STATE CONVERSION")
    print("=" * 80)
    
    from modules.cyber_attack_graph import _context_from_state, _state_from_context
    from modules.agent_langgraph_wrapper import AgentContext
    
    # Create a state dict
    state = {
        "input_type": "cve",
        "cve_id": "CVE-2008-0888",
        "file_path": "",
        "error_message": "",
        "execution_log": ["test"],
        "connections_ok": True
    }
    
    # Convert to context
    ctx = _context_from_state(state)
    
    print("✅ Converted state dict to AgentContext")
    print(f"   Input type: {ctx.input_type}")
    print(f"   CVE ID: {ctx.cve_id}")
    
    assert ctx.input_type == "cve"
    assert ctx.cve_id == "CVE-2008-0888"
    
    # Convert back to state
    new_state = _state_from_context(ctx)
    
    print("✅ Converted AgentContext back to state dict")
    print(f"   Input type: {new_state['input_type']}")
    print(f"   CVE ID: {new_state['cve_id']}")
    
    assert new_state["input_type"] == "cve"
    assert new_state["cve_id"] == "CVE-2008-0888"
    
    print("✅ State conversion works bidirectionally")
    print()
    return True


def test_file_target_spec_creation():
    """Test file mode target preparation creates a Docker local-file spec"""
    print("\n" + "=" * 80)
    print("TEST 5: FILE TARGET SPEC")
    print("=" * 80)

    from modules.agent_langgraph_wrapper import CyberAttackAgentWrapper, AgentContext

    file_path = project_root / "demos" / "vulnerable_example.c"
    ctx = AgentContext(file_path=str(file_path))
    ctx = CyberAttackAgentWrapper().prepare_target_environment_step(ctx)

    print(f"✅ Target state: {ctx.current_state.value}")
    print(f"   Target type: {ctx.target_spec.get('target_type')}")

    assert ctx.current_state.value == "target_ready"
    assert ctx.target_spec["mode"] == "file"
    assert ctx.target_spec["target_type"] == "local_file"
    assert ctx.target_spec["container_target_path"] == "/tmp/target.c"
    assert "gcc" in ctx.target_spec["compile_command"]

    print("✅ File target spec created correctly")
    print()
    return True


def test_unresolved_cve_target_spec():
    """Test unresolved CVE reproduction produces a non-executable TargetSpec"""
    print("\n" + "=" * 80)
    print("TEST 6: UNRESOLVED CVE TARGET SPEC")
    print("=" * 80)

    from modules.agent_langgraph_wrapper import CyberAttackAgentWrapper, AgentContext

    wrapper = CyberAttackAgentWrapper()
    ctx = AgentContext(cve_id="CVE-2008-0888")
    ctx.cwe_id = "CWE-119"
    ctx.cve_target_info = {"missing_fields": ["source_or_build_reference"]}
    ctx = wrapper.plan_reproduction_step(ctx)
    ctx = wrapper.build_target_artifact_step(ctx)

    print(f"✅ Target state: {ctx.current_state.value}")
    print(f"   Target type: {ctx.target_spec.get('target_type')}")

    assert ctx.current_state.value == "target_unresolved"
    assert ctx.target_spec["mode"] == "cve"
    assert ctx.target_spec["target_type"] == "unresolved_cve"
    assert ctx.target_spec["build_strategy"] == "needs_reproduction_plan"

    print("✅ Unresolved CVE target spec created correctly")
    print()
    return True


def test_run_cyber_attack_signature():
    """Test that run_cyber_attack accepts the correct parameters"""
    print("\n" + "=" * 80)
    print("TEST 7: RUN_CYBER_ATTACK SIGNATURE")
    print("=" * 80)
    
    from modules.cyber_attack_graph import run_cyber_attack
    import inspect
    
    # Check function signature
    sig = inspect.signature(run_cyber_attack)
    params = list(sig.parameters.keys())
    
    print(f"✅ Function parameters: {params}")
    
    assert "file_path" in params, "Should accept file_path"
    assert "cve_id" in params, "Should accept cve_id"
    assert "user_input" in params, "Should accept user_input"
    
    print("✅ Function signature is correct")
    print("   - file_path: Optional[str] = None")
    print("   - cve_id: Optional[str] = None")
    print("   - user_input: Optional[str] = None")
    print()
    return True


def main():
    """Run all tests"""
    print("=" * 80)
    print("QUICK INTEGRATION TESTS (NO LLM)")
    print("=" * 80)
    
    tests = [
        ("File Mode Routing", test_file_mode_routing),
        ("CVE Mode Routing", test_cve_mode_routing),
        ("Invalid Input Rejection", test_invalid_input_rejection),
        ("State Conversion", test_graph_state_conversion),
        ("File Target Spec", test_file_target_spec_creation),
        ("Unresolved CVE Target Spec", test_unresolved_cve_target_spec),
        ("Function Signature", test_run_cyber_attack_signature),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✅ {name}: PASSED")
            else:
                failed += 1
                print(f"❌ {name}: FAILED")
        except Exception as e:
            failed += 1
            print(f"❌ {name}: FAILED")
            print(f"   Error: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"Total: {len(tests)}")
    print()
    
    if failed == 0:
        print("🎉 ALL TESTS PASSED!")
        print()
        print("The dual input mode is working correctly:")
        print("  ✅ File mode routing works")
        print("  ✅ CVE mode routing works")
        print("  ✅ Invalid input is rejected")
        print("  ✅ State conversion is bidirectional")
        print("  ✅ Target specs are produced")
        print("  ✅ Function signatures are correct")
        print()
        return True
    else:
        print("⚠️  SOME TESTS FAILED")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
