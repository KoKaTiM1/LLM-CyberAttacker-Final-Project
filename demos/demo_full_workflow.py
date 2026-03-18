"""
Full Workflow Demo - Complete CVE to Exploit Pipeline
=====================================================

This demo runs the complete workflow:
1. Check API connections
2. Load CVE data from database
3. Build dynamic prompts with Orchestrator
4. Validate CVE support
5. Generate exploit using LLM with expert prompts
6. Show results

Using: CVE-2008-0888 (Buffer Overflow)
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from modules.agent_langgraph_wrapper import CyberAttackAgentWrapper, AgentContext
from modules.cve_database import CVEDatabase
import json

def print_header(text, char="="):
    """Print formatted header"""
    print("\n" + char * 80)
    print(f"  {text}")
    print(char * 80 + "\n")

def print_step(step_num, text):
    """Print step header"""
    print(f"\n{'─' * 80}")
    print(f"  STEP {step_num}: {text}")
    print('─' * 80)

def show_cve_details(cve_id):
    """Show CVE details from database"""
    print_step(0, "CVE Information")
    
    db = CVEDatabase()
    cve_data = db.get_by_id(cve_id)
    
    if not cve_data:
        print(f"❌ CVE {cve_id} not found!")
        return None
    
    # Extract details
    desc = ""
    if 'descriptions' in cve_data:
        for d in cve_data['descriptions']:
            if d.get('lang') == 'en':
                desc = d.get('value', '')[:200] + "..."
    
    # Extract CWE
    cwe = "Unknown"
    if 'weaknesses' in cve_data:
        for weakness in cve_data.get('weaknesses', []):
            for d in weakness.get('description', []):
                if d.get('value', '').startswith('CWE-'):
                    cwe = d['value']
                    break
    
    print(f"📋 CVE ID: {cve_id}")
    print(f"🎯 CWE Type: {cwe}")
    print(f"📝 Description:\n   {desc}")
    
    return cve_data

def main():
    print_header("🚀 FULL WORKFLOW EXECUTION DEMO")
    print("This demo shows the complete CVE-to-Exploit pipeline in action.")
    print("Target: CVE-2008-0888 (Buffer Overflow)")
    
    # Show CVE details
    cve_id = "CVE-2008-0888"
    cve_data = show_cve_details(cve_id)
    
    if not cve_data:
        return 1
    
    input("\nPress Enter to start the workflow...")
    
    # Create workflow and context
    print_step(1, "Initializing Workflow")
    agent = CyberAttackAgentWrapper()
    context = AgentContext(cve_id=cve_id)
    print("✅ Workflow initialized")
    
    # Run workflow step by step with visual feedback
    print_step(2, "Checking API Connections")
    context = agent.check_connections_step(context)
    
    if context.error_message:
        print(f"❌ {context.error_message}")
        return 1
    
    print("✅ All connections successful")
    
    print_step(3, "Loading CVE from Database")
    context = agent.load_cve_step(context)
    
    if context.error_message:
        print(f"❌ {context.error_message}")
        return 1
    
    print(f"✅ CVE loaded and validated")
    print(f"   CWE extracted from CVE data")
    
    print_step(4, "Building Dynamic Prompts with Orchestrator")
    context = agent.build_prompt_step(context)
    
    if context.error_message:
        print(f"❌ {context.error_message}")
        return 1
    
    print(f"✅ Prompts assembled")
    print(f"   Expert Profile: {context.prompt_metadata.get('expert_profile')}")
    print(f"   Vulnerability Logic: {context.prompt_metadata.get('vulnerability_logic')}")
    print(f"   Category: {context.prompt_metadata.get('category')}")
    
    # Show system prompt preview
    print("\n📄 System Prompt Preview (first 300 chars):")
    print("   " + "-" * 76)
    prompt_preview = context.system_prompt[:300].replace('\n', '\n   ')
    print(f"   {prompt_preview}...")
    print("   " + "-" * 76)
    
    print_step(5, "Validating File (Optional)")
    context = agent.validate_file_step(context)
    
    if context.error_message and "CVE-only mode" not in context.error_message:
        print(f"❌ {context.error_message}")
        return 1
    
    print("✅ Validation passed (CVE-only mode)")
    
    print_step(6, "Analyzing Vulnerability with LLM")
    print("⏳ Sending prompts to LLM... (this may take 30-60 seconds)")
    print("   Using expert knowledge for buffer overflow exploitation")
    
    context = agent.analyze_vulnerability_step(context)
    
    if context.error_message:
        print(f"❌ {context.error_message}")
        return 1
    
    print("✅ LLM analysis complete")
    
    # Show LLM response preview
    if context.vulnerability_data:
        print("\n📊 Vulnerability Analysis Result:")
        print("   " + "-" * 76)
        if isinstance(context.vulnerability_data, dict):
            print(f"   Structured data received")
            if 'vulnerabilities' in context.vulnerability_data:
                print(f"   Found {len(context.vulnerability_data['vulnerabilities'])} vulnerabilities")
        else:
            print(f"   Response type: {type(context.vulnerability_data)}")
        print("   " + "-" * 76)
    
    print_step(7, "Generating Exploit Script")
    print("⏳ Creating exploit code... (this may take 30-60 seconds)")
    
    context = agent.create_attack_script_step(context)
    
    if context.error_message:
        print(f"❌ {context.error_message}")
        return 1
    
    print("✅ Exploit script generated")
    
    # Show exploit preview
    if context.attack_script:
        lines = context.attack_script.split('\n')
        preview_lines = min(30, len(lines))
        
        print(f"\n📜 Generated Exploit Script (first {preview_lines} lines):")
        print("   " + "=" * 76)
        for i, line in enumerate(lines[:preview_lines], 1):
            print(f"   {i:3d} | {line}")
        
        if len(lines) > preview_lines:
            print(f"   ... ({len(lines) - preview_lines} more lines)")
        
        print("   " + "=" * 76)
        print(f"\n📊 Script Statistics:")
        print(f"   Total lines: {len(lines)}")
        print(f"   Total characters: {len(context.attack_script)}")
    
    # Final summary
    print_header("✅ WORKFLOW COMPLETED SUCCESSFULLY", "=")
    
    print("Summary:")
    print(f"  • CVE: {cve_id}")
    print(f"  • CWE: {context.cwe_id}")
    print(f"  • Category: {context.prompt_metadata.get('category')}")
    print(f"  • Expert Profile: {context.prompt_metadata.get('expert_profile')}")
    print(f"  • Exploit Generated: {'✅ Yes' if context.attack_script else '❌ No'}")
    
    print("\nWorkflow Steps Executed:")
    for i, log in enumerate(context.execution_log, 1):
        print(f"  {i}. {log}")
    
    # Save exploit to file
    if context.attack_script:
        output_file = Path(__file__).parent / f"exploit_{cve_id.replace('-', '_')}.py"
        output_file.write_text(context.attack_script, encoding='utf-8')
        print(f"\n💾 Exploit saved to: {output_file}")
    
    print("\n" + "=" * 80)
    print("🎉 Demo Complete!")
    print("=" * 80)
    
    return 0

if __name__ == "__main__":
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️ Demo interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
