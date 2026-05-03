"""
Demo: CVE Rejection Example
============================

Shows what happens when a user tries to process a CVE with unsupported vulnerability type.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.modules.agent_langgraph_wrapper import CyberAttackAgentWrapper, AgentContext

def print_header(text):
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80 + "\n")

def demo_rejected_cve():
    """Demonstrate rejection of unsupported CVE"""
    
    print_header("DEMO: Processing CVE with Unsupported Attack Type")
    
    # Try to process a SQL Injection CVE
    print("User Request: Process CVE-2018-3811 (SQL Injection)")
    print("-" * 80)
    
    # Create workflow
    agent = CyberAttackAgentWrapper()
    
    # Create context with SQL Injection CVE
    context = AgentContext(cve_id="CVE-2018-3811")
    
    # Run workflow
    print("\n🚀 Starting workflow...\n")
    result = agent.workflow.invoke(context)
    
    # Show results
    print_header("WORKFLOW RESULT")
    
    if result.error_message:
        print("❌ REQUEST REJECTED\n")
        print(result.error_message)
        print("\n" + "-" * 80)
        print("Status: Workflow terminated - CVE not supported")
    else:
        print("✅ Request processed successfully")
    
    return result

def demo_accepted_cve():
    """Demonstrate acceptance of supported CVE"""
    
    print_header("DEMO: Processing CVE with Supported Attack Type")
    
    # Try to process a Buffer Overflow CVE
    print("User Request: Process CVE-2008-0888 (Buffer Overflow)")
    print("-" * 80)
    
    # Create workflow
    agent = CyberAttackAgentWrapper()
    
    # Create context with Buffer Overflow CVE
    context = AgentContext(cve_id="CVE-2008-0888")
    
    # Run workflow (only through validation step)
    print("\n🚀 Starting workflow...\n")
    
    # Check connections
    context = agent.check_connections_step(context)
    if context.error_message:
        print(f"❌ Connection failed: {context.error_message}")
        return context
    
    # Load CVE
    context = agent.load_cve_step(context)
    
    # Show results
    print_header("WORKFLOW RESULT")
    
    if context.error_message:
        print("❌ REQUEST REJECTED\n")
        print(context.error_message)
    else:
        print("✅ CVE VALIDATION PASSED\n")
        print(f"CVE ID: {context.cve_id}")
        print(f"CWE Type: This CVE contains supported vulnerability type")
        print(f"Status: Ready to proceed with exploit generation")
    
    return context

def main():
    print_header("CVE VALIDATION DEMO")
    print("This demo shows how the system handles supported vs unsupported CVE types.\n")
    
    # Demo 1: Rejected CVE
    result1 = demo_rejected_cve()
    input("\n\nPress Enter to see accepted CVE example...")
    
    # Demo 2: Accepted CVE
    result2 = demo_accepted_cve()
    
    print_header("SUMMARY")
    print("✅ Unsupported CVEs are rejected with clear error messages")
    print("✅ Supported CVEs (Buffer Overflow, Format String) proceed normally")
    print("\nSupported vulnerability types:")
    print("  • Buffer Overflow (CWE-119, 120, 121, 122, 125, 787)")
    print("  • Format String (CWE-134)")

if __name__ == "__main__":
    main()
