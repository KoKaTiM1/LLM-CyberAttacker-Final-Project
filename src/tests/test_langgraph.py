#!/usr/bin/env python3
"""
Test script for the LangGraph wrapper implementation
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from src.modules.agent_langgraph_wrapper import CyberAttackAgentWrapper
import json

def test_langgraph_wrapper():
    """Test the LangGraph wrapper with a sample file"""
    print("🚀 Testing LangGraph CyberAttack Wrapper")
    print("=" * 50)
    
    # Create wrapper instance
    wrapper = CyberAttackAgentWrapper()
    
    # First, let's manually install pwntools in the sandboxes
    print("📦 Installing pwntools in sandbox environments...")
    install_script = """
import subprocess
import sys

try:
    # Try importing pwntools first
    import pwn
    print("✅ pwntools is already installed")
except ImportError:
    print("📦 Installing pwntools...")
    try:
        # Install pwntools
        result = subprocess.run([sys.executable, "-m", "pip", "install", 
                              "pwntools"], capture_output=True, text=True, 
                              timeout=120)
        if result.returncode == 0:
            print("✅ pwntools installation successful")
            print("Installation output:", result.stdout)
        else:
            print("❌ pwntools installation failed")
            print("Error:", result.stderr)
    except Exception as e:
        print(f"❌ Installation error: {e}")

# Test basic functionality
try:
    from pwn import *
    print("✅ pwntools import successful")
    print("🔧 Testing basic pwntools functions...")
    test_data = b"AAAA"
    packed = p32(0x41414141)
    print(f"✅ p32(0x41414141) = {packed.hex()}")
except Exception as e:
    print(f"❌ pwntools test failed: {e}")
"""
    
    # Try to install pwntools in the sandbox first
    try:
        from src.modules.sandbox import SandboxManager
        config_dir = os.path.join(os.path.dirname(__file__), '..', '..')
        sandbox_config_path = os.path.join(config_dir, 'src', 'config',
                                           'sandbox_config.json')
        
        if os.path.exists(sandbox_config_path):
            sandbox = SandboxManager(sandbox_config_path)
            print("🔧 Installing pwntools in sandbox environments...")
            
            # Run installation script in sandbox
            if sandbox.connect_all():
                results = sandbox.run_test_on_all(install_script)
                for env_name, result in results.items():
                    if result.success:
                        print(f"✅ {env_name}: pwntools check completed")
                    else:
                        print(f"⚠️  {env_name}: {result.error}")
                sandbox.disconnect_all()
            else:
                print("⚠️  Could not connect to sandbox environments")
        else:
            print(f"⚠️  Sandbox config not found at {sandbox_config_path}")
            
    except Exception as e:
        print(f"⚠️  Sandbox pwntools installation failed: {e}")
    
    # Test with a sample file from the dataset (absolute path)
    test_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'LCP-Data set', 'Files', 'File1.txt'))
    
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
            attack_type = type(result['attack_instance']).__name__
            print(f"✅ Attack instance created: {attack_type}")
            
        if result.get('sandbox_result'):
            print("✅ Sandbox execution completed")
            
        # Print workflow steps
        print("\n📝 Workflow Steps:")
        print("-" * 20)
        for i, step in enumerate(result.get('steps_log', []), 1):
            print(f"{i}. {step}")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    test_langgraph_wrapper()
