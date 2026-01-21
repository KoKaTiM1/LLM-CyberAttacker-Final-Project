"""
Demo script for Prompt Orchestrator
Demonstrates how to use the orchestrator with different types of CVEs
"""

import sys
import os
import json

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from modules.orchestrator import PromptOrchestrator


def print_separator(title=""):
    """Print a formatted separator"""
    print("\n" + "=" * 80)
    if title:
        print(f" {title}")
        print("=" * 80)
    print()


def demo_buffer_overflow():
    """Demo: Buffer Overflow CVE"""
    print_separator("DEMO 1: Buffer Overflow (CWE-119)")
    
    cve_data = {
        'id': 'CVE-2024-DEMO-001',
        'cwe': 'CWE-119',
        'descriptions': [
            {
                'lang': 'en',
                'value': 'A stack-based buffer overflow in the parse_input() function of MyApp v1.0 allows remote attackers to execute arbitrary code via a crafted HTTP request with an overly long username parameter.'
            }
        ],
        'metrics': {
            'cvssMetricV31': [
                {
                    'cvssData': {
                        'baseScore': 9.8,
                        'baseSeverity': 'CRITICAL'
                    }
                }
            ]
        },
        'references': [
            {'url': 'https://example.com/advisory-001'},
            {'url': 'https://github.com/vendor/myapp/security/advisories/001'}
        ]
    }
    
    orchestrator = PromptOrchestrator()
    prompt = orchestrator.assemble_prompt(cve_data)
    
    print("📋 METADATA:")
    print(json.dumps(prompt.metadata, indent=2))
    
    print("\n💡 SYSTEM PROMPT (first 300 chars):")
    print(prompt.system_prompt[:300] + "...")
    
    print("\n📝 USER PROMPT (first 500 chars):")
    print(prompt.user_prompt[:500] + "...")
    
    return prompt


def demo_sql_injection():
    """Demo: SQL Injection CVE"""
    print_separator("DEMO 2: SQL Injection (CWE-89)")
    
    cve_data = {
        'id': 'CVE-2024-DEMO-002',
        'weaknesses': [
            {
                'description': [
                    {'lang': 'en', 'value': 'CWE-89'}
                ]
            }
        ],
        'descriptions': [
            {
                'lang': 'en',
                'value': 'SQL injection vulnerability in the login module of WebPortal v2.5 allows authenticated users to execute arbitrary SQL commands via the search parameter.'
            }
        ],
        'metrics': {
            'cvssMetricV31': [
                {
                    'cvssData': {
                        'baseScore': 8.8,
                        'baseSeverity': 'HIGH'
                    }
                }
            ]
        }
    }
    
    orchestrator = PromptOrchestrator()
    prompt = orchestrator.assemble_prompt(cve_data)
    
    print("📋 METADATA:")
    print(json.dumps(prompt.metadata, indent=2))
    
    print("\n💡 EXPERT ASSIGNED:")
    if 'Web Application Security Expert' in prompt.system_prompt:
        print("✓ Web Application Security Expert")
    
    print("\n📖 METHODOLOGY INCLUDED:")
    if 'SQL Injection' in prompt.user_prompt:
        print("✓ SQL Injection Exploitation Methodology")
    
    return prompt


def demo_xss():
    """Demo: Cross-Site Scripting CVE"""
    print_separator("DEMO 3: Cross-Site Scripting (CWE-79)")
    
    cve_data = {
        'id': 'CVE-2024-DEMO-003',
        'cwe': 'CWE-79',
        'description': 'Stored XSS vulnerability in comment section allows attackers to inject malicious JavaScript',
        'cvss_score': '6.1 (MEDIUM)'
    }
    
    orchestrator = PromptOrchestrator()
    
    # Add custom instructions
    custom = """
Target environment:
- Modern web browser (Chrome/Firefox)
- User is logged in as administrator
- CSP is not implemented
Focus on demonstrating session hijacking impact.
"""
    
    prompt = orchestrator.assemble_prompt(cve_data, custom_instructions=custom)
    
    print("📋 METADATA:")
    print(json.dumps(prompt.metadata, indent=2))
    
    print("\n✨ CUSTOM INSTRUCTIONS INCLUDED:")
    print("✓ Custom instructions were added to the prompt")
    
    print("\n📝 USER PROMPT (showing custom instructions):")
    if 'Additional Instructions' in prompt.user_prompt:
        start = prompt.user_prompt.find('## Additional Instructions')
        end = prompt.user_prompt.find('##', start + 1)
        print(prompt.user_prompt[start:end if end != -1 else start+300])
    
    return prompt


def demo_use_after_free():
    """Demo: Use After Free CVE"""
    print_separator("DEMO 4: Use After Free (CWE-416)")
    
    cve_data = {
        'id': 'CVE-2024-DEMO-004',
        'cwe': 'CWE-416',
        'descriptions': [
            {
                'lang': 'en',
                'value': 'Use-after-free vulnerability in BrowserEngine v3.0 when processing DOM elements allows remote code execution through crafted HTML pages.'
            }
        ],
        'metrics': {
            'cvssMetricV31': [
                {
                    'cvssData': {
                        'baseScore': 9.8,
                        'baseSeverity': 'CRITICAL'
                    }
                }
            ]
        }
    }
    
    orchestrator = PromptOrchestrator()
    prompt = orchestrator.assemble_prompt(cve_data)
    
    print("📋 METADATA:")
    print(json.dumps(prompt.metadata, indent=2))
    
    print("\n🎯 SPECIALIZED EXPERT:")
    if 'Memory Corruption Specialist' in prompt.system_prompt:
        print("✓ Memory Corruption Specialist assigned")
    
    print("\n🧠 EXPLOITATION FOCUS:")
    if 'Use-After-Free' in prompt.user_prompt or 'heap' in prompt.user_prompt.lower():
        print("✓ UAF-specific methodology included")
    
    return prompt


def demo_unknown_cwe():
    """Demo: CVE without CWE (uses default)"""
    print_separator("DEMO 5: Unknown Vulnerability (No CWE - Default Expert)")
    
    cve_data = {
        'id': 'CVE-2024-DEMO-005',
        'descriptions': [
            {
                'lang': 'en',
                'value': 'Critical vulnerability in CustomApp v1.0 allows unauthorized access to sensitive data.'
            }
        ]
    }
    
    orchestrator = PromptOrchestrator()
    prompt = orchestrator.assemble_prompt(cve_data)
    
    print("📋 METADATA:")
    print(json.dumps(prompt.metadata, indent=2))
    
    print("\n⚠️ FALLBACK BEHAVIOR:")
    print("✓ No CWE found - using default expert profile")
    print("✓ General exploitation approach will be used")
    
    return prompt


def show_available_mappings():
    """Show all available CWE mappings"""
    print_separator("AVAILABLE CWE MAPPINGS")
    
    orchestrator = PromptOrchestrator()
    mappings = orchestrator.get_available_cwe_mappings()
    categories = orchestrator.get_categories()
    
    print(f"📊 Total CWE Mappings: {len(mappings)}\n")
    
    # Group by category
    by_category = {}
    for cwe_id in mappings:
        mapping = orchestrator.mapping_config['mappings'][cwe_id]
        category = mapping.get('category', 'other')
        if category not in by_category:
            by_category[category] = []
        by_category[category].append((cwe_id, mappings[cwe_id]))
    
    for category, cwes in sorted(by_category.items()):
        cat_info = categories.get(category, {})
        print(f"\n🏷️  {category.upper().replace('_', ' ')}")
        if 'description' in cat_info:
            print(f"   {cat_info['description']}")
        print()
        for cwe_id, name in sorted(cwes):
            print(f"   • {cwe_id}: {name}")


def main():
    """Run all demos"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    PROMPT ORCHESTRATOR DEMONSTRATION                          ║
║                                                                              ║
║  This demo shows how the orchestrator dynamically assembles prompts based   ║
║  on CVE/CWE data by selecting appropriate expert profiles and exploitation  ║
║  methodologies.                                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Show available mappings first
        show_available_mappings()
        
        # Run demos
        demo_buffer_overflow()
        demo_sql_injection()
        demo_xss()
        demo_use_after_free()
        demo_unknown_cwe()
        
        print_separator("DEMO COMPLETE")
        print("""
✅ All demonstrations completed successfully!

Key Features Demonstrated:
1. ✓ CWE extraction from different CVE formats
2. ✓ Automatic expert profile selection
3. ✓ Vulnerability-specific methodology inclusion
4. ✓ Custom instructions integration
5. ✓ Fallback to default expert for unknown CWEs
6. ✓ Comprehensive metadata tracking

Next Steps:
- Integrate with your LLM API (OpenAI, Anthropic, etc.)
- Use assembled prompts for exploit generation
- Extend mappings with more CWE types
- Customize expert profiles for your needs
""")
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
