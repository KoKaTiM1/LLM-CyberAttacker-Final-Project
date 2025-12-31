"""
Test sandbox.py AS-IS - without any modifications
Just pass the original exploit.py to all sandboxes and see what happens
"""

import sys
import os
import logging

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from modules.sandbox import SandboxManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Test sandbox execution with original exploit.py - no modifications"""
    
    config_path = r"src\config\sandbox_config.json"
    exploit_path = "exploit.py"
    
    print("=" * 80)
    print("TESTING SANDBOX.PY AS-IS")
    print("Testing with original exploit.py (no modifications)")
    print("=" * 80)
    
    # Read original exploit
    print("\n[1] Reading original exploit.py...")
    with open(exploit_path, 'r', encoding='utf-8') as f:
        exploit_script = f.read()
    
    print(f"✓ Read {len(exploit_script)} bytes")
    print("\n--- Original exploit.py content (first 500 chars) ---")
    print(exploit_script[:500])
    print("..." if len(exploit_script) > 500 else "")
    
    # Initialize sandbox manager
    print("\n[2] Initializing Sandbox Manager...")
    try:
        sandbox_manager = SandboxManager(config_path)
        print(f"✓ Sandbox Manager initialized")
        # environments is a dict, not a list
        env_names = ', '.join(sandbox_manager.environments.keys())
        print(f"  Available environments: {env_names}")
    except Exception as e:
        print(f"✗ Failed to initialize: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Connect to all sandboxes
    print("\n[3] Connecting to sandboxes...")
    overall_success = sandbox_manager.connect_all()
    
    # Check which ones connected
    connected_count = 0
    for env_name, env in sandbox_manager.environments.items():
        status = "✓" if env.is_connected else "✗"
        print(f"  {status} {env_name}: {'Connected' if env.is_connected else 'Failed'}")
        if env.is_connected:
            connected_count += 1
    
    if connected_count == 0:
        print("\n✗ No sandboxes connected. Exiting.")
        return
    
    # Execute ORIGINAL exploit in all connected sandboxes
    print("\n[4] Executing ORIGINAL exploit.py in all sandboxes...")
    print("=" * 80)
    
    results = {}
    
    for env_name, env in sandbox_manager.environments.items():
        if not env.is_connected:
            print(f"\n[{env.name}] Skipped (not connected)")
            continue
        
        print(f"\n{'=' * 80}")
        print(f"EXECUTING IN: {env.name}")
        print(f"{'=' * 80}")
        
        try:
            # Execute the ORIGINAL exploit script - NO MODIFICATIONS
            print(f"[*] Passing original exploit.py to {env.name}...")
            result = env.execute_script(exploit_script, file_type="python")
            results[env.name] = result
            
            print(f"\n--- Results for {env.name} ---")
            print(f"Success: {result.success}")
            print(f"Execution Time: {result.execution_time:.2f}s")
            print(f"\n--- Output ---")
            print(result.output if result.output else "(no output)")
            
            if result.error:
                print(f"\n--- Error ---")
                print(result.error)
            
            # Analysis
            print(f"\n--- Analysis ---")
            if result.success:
                print("✓ Script executed without errors")
            else:
                print("✗ Script execution failed")
                if result.error:
                    if "FileNotFoundError" in result.error:
                        print("  → Missing file (expected: ./vulnerable_binary)")
                    elif "ModuleNotFoundError" in result.error or "ImportError" in result.error:
                        print("  → Missing Python module")
                    elif "No such file" in result.error:
                        print("  → File not found error")
                    else:
                        print(f"  → Other error: {result.error.split('\\n')[0][:100]}")
                
        except Exception as e:
            print(f"\n✗ Exception in {env.name}: {e}")
            results[env.name] = None
    
    # Disconnect
    print("\n[5] Disconnecting from sandboxes...")
    disconnect_success = sandbox_manager.disconnect_all()
    
    for env_name, env in sandbox_manager.environments.items():
        status = "✓" if not env.is_connected else "✗"
        print(f"  {status} {env_name}")
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY - WHAT HAPPENED?")
    print("=" * 80)
    
    for env_name, result in results.items():
        if result:
            status = "✓ SUCCESS" if result.success else "✗ FAILED"
            print(f"\n{env_name}: {status}")
            print(f"  Execution Time: {result.execution_time:.2f}s")
            
            if not result.success and result.error:
                # Identify the problem
                error_lower = result.error.lower()
                if "filenotfounderror" in error_lower or "no such file" in error_lower:
                    print("  Problem: Missing vulnerable_binary file")
                    print("  → The exploit expects './vulnerable_binary' to exist")
                    print("  → But sandbox.py doesn't compile C code automatically")
                elif "modulenotfounderror" in error_lower or "no module named" in error_lower:
                    print("  Problem: Missing Python modules")
                    if "pwn" in error_lower:
                        print("  → pwntools is not installed")
                else:
                    print(f"  Problem: {result.error.split(chr(10))[0][:100]}")
        else:
            print(f"\n{env_name}: ✗ NOT EXECUTED")
    
    print("\n" + "=" * 80)
    print("CONCLUSION")
    print("=" * 80)
    print("""
The original exploit.py expects:
1. A compiled binary at './vulnerable_binary'
2. pwntools library installed

Current sandbox.py behavior:
- ✓ Can execute Python scripts
- ✓ Can install packages (pwntools)
- ✗ Does NOT automatically compile C code
- ✗ Does NOT prepare the vulnerable binary

This is the AS-IS behavior - no modifications, just testing what exists.
    """)


if __name__ == "__main__":
    main()
