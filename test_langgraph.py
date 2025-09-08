#!/usr/bin/env python3
"""
Test script for the LangGraph wrapper implementation
"""

from agent_langgraph_wrapper import CyberAttackAgentWrapper
import json

def test_langgraph_wrapper():
    """Test the LangGraph wrapper with a sample file"""
    print("🚀 Testing LangGraph CyberAttack Wrapper")
    print("=" * 50)
    
    # Create wrapper instance
    wrapper = CyberAttackAgentWrapper()
    
    # Test with a sample file from the dataset
    test_file = "LCP-Data set/Files/File1.txt"
    
    try:
        # Run the analysis workflow
        result = wrapper.run_analysis(test_file)
        
        print("\n📊 Workflow Results:")
        print("=" * 30)
        print(f"Final State: {result.get('final_state', 'Unknown')}")
        print(f"Success: {result.get('success', False)}")
        print(f"Steps Completed: {len(result.get('steps_log', []))}")
        
        if result.get('error'):
            print(f"❌ Error: {result.get('error')}")
        
        if result.get('attack_instance'):
            print(f"✅ Attack instance created: {type(result['attack_instance']).__name__}")
            
        if result.get('sandbox_result'):
            print(f"✅ Sandbox execution completed")
            
        # Print workflow steps
        print("\n📝 Workflow Steps:")
        print("-" * 20)
        for i, step in enumerate(result.get('steps_log', []), 1):
            print(f"{i}. {step}")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    test_langgraph_wrapper()
