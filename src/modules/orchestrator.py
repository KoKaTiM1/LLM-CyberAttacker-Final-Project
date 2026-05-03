"""
Prompt Orchestrator - Dynamic Prompt Assembly for CVE Exploitation

This module provides intelligent prompt composition by mapping CVE/CWE data to 
appropriate expert profiles and vulnerability exploitation methodologies.

The orchestrator:
1. Extracts CWE from CVE data
2. Maps CWE to expert profile and exploitation logic
3. Loads relevant content from files
4. Assembles a comprehensive, context-aware prompt
"""

import json
import logging
from pathlib import Path
from typing import Dict, Optional, Tuple
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class PromptComponents:
    """Container for assembled prompt components"""
    expert_profile: str
    vulnerability_logic: Optional[str]
    cve_context: str
    cwe_id: Optional[str]
    category: Optional[str]


@dataclass
class AssembledPrompt:
    """Complete assembled prompt ready for LLM"""
    system_prompt: str
    user_prompt: str
    metadata: Dict


class PromptOrchestrator:
    """
    Orchestrates dynamic prompt assembly based on CVE/CWE mapping
    """
    
    def __init__(self, 
                 config_path: Optional[str] = None,
                 expert_profiles_dir: Optional[str] = None,
                 vulnerability_logic_dir: Optional[str] = None):
        """
        Initialize the orchestrator with paths to configuration and content directories
        
        Args:
            config_path: Path to CWE mapping JSON file
            expert_profiles_dir: Directory containing expert profile text files
            vulnerability_logic_dir: Directory containing vulnerability logic text files
        """
        # Set default paths relative to this file
        base_dir = Path(__file__).parent.parent
        
        self.config_path = Path(config_path) if config_path else base_dir / "config" / "cwe_mapping.json"
        self.expert_profiles_dir = Path(expert_profiles_dir) if expert_profiles_dir else base_dir / "expert_profiles"
        self.vulnerability_logic_dir = Path(vulnerability_logic_dir) if vulnerability_logic_dir else base_dir / "vulnerability_logic"
        
        # Load mapping configuration
        self.mapping_config = self._load_mapping_config()
        
        logger.info(f"Orchestrator initialized with:")
        logger.info(f"  Config: {self.config_path}")
        logger.info(f"  Expert Profiles: {self.expert_profiles_dir}")
        logger.info(f"  Vulnerability Logic: {self.vulnerability_logic_dir}")
        logger.info(f"  Supported CWEs: {self.get_supported_cwe_list()}")
    
    def is_cwe_supported(self, cwe_id: str) -> bool:
        """
        Check if a CWE is currently supported by the system
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-119")
            
        Returns:
            True if supported, False otherwise
        """
        if not cwe_id:
            return False
        
        supported_list = self.mapping_config.get('supported_cwe_list', [])
        mappings = self.mapping_config.get('mappings', {})
        
        # Check if CWE is in supported list and enabled in mappings
        is_in_list = cwe_id in supported_list
        is_enabled = mappings.get(cwe_id, {}).get('enabled', False)
        
        supported = is_in_list and is_enabled
        
        if not supported:
            logger.warning(f"CWE {cwe_id} is NOT supported")
            if cwe_id in self.mapping_config.get('disabled_mappings', {}):
                reason = self.mapping_config['disabled_mappings'][cwe_id].get('reason', 'Unknown')
                logger.info(f"  Reason: {reason}")
        
        return supported
    
    def get_supported_cwe_list(self) -> list:
        """
        Get list of all supported CWE IDs
        
        Returns:
            List of CWE ID strings
        """
        return self.mapping_config.get('supported_cwe_list', [])
    
    def validate_cve_support(self, cve_data: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate if a CVE is supported based on its CWE type
        
        Args:
            cve_data: CVE data dictionary
            
        Returns:
            Tuple of (is_supported: bool, error_message: Optional[str])
        """
        # Extract CWE from CVE
        cwe_id = self._extract_cwe_from_cve(cve_data)
        
        if not cwe_id:
            return False, "ERROR: CVE does not contain a CWE identifier. Cannot process."
        
        # Check if supported
        if not self.is_cwe_supported(cwe_id):
            cve_id = cve_data.get('id') or cve_data.get('cve', {}).get('id', 'Unknown')
            
            # Get reason from disabled mappings if available
            disabled = self.mapping_config.get('disabled_mappings', {})
            reason = "This vulnerability type is not currently supported."
            
            if cwe_id in disabled:
                cwe_name = disabled[cwe_id].get('name', cwe_id)
                reason = disabled[cwe_id].get('reason', reason)
            else:
                cwe_name = cwe_id
            
            error_msg = f"""
ERROR: CVE {cve_id} cannot be processed.

Vulnerability Type: {cwe_name} ({cwe_id})
Reason: {reason}

Currently supported vulnerability types:
- Buffer Overflow (CWE-119, CWE-120, CWE-121, CWE-122, CWE-125, CWE-787)
- Format String (CWE-134)

Please select a CVE with one of the supported vulnerability types.
"""
            return False, error_msg.strip()
        
        return True, None
    
    def _load_mapping_config(self) -> Dict:
        """Load the CWE to expert/logic mapping configuration"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                logger.info(f"Loaded mapping config with {len(config.get('mappings', {}))} CWE mappings")
                return config
        except FileNotFoundError:
            logger.error(f"Mapping config not found at {self.config_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in mapping config: {e}")
            raise
    
    def _extract_cwe_from_cve(self, cve_data: Dict) -> Optional[str]:
        """
        Extract CWE ID from CVE data
        
        Args:
            cve_data: CVE data dictionary (can be from NVD API or other sources)
            
        Returns:
            CWE ID string (e.g., "CWE-119") or None if not found
        """
        # Try multiple common formats
        
        # Format 1: NVD API 2.0 format
        if 'weaknesses' in cve_data:
            for weakness in cve_data.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    if desc.get('value', '').startswith('CWE-'):
                        cwe_id = desc['value']
                        logger.debug(f"Found CWE from weaknesses: {cwe_id}")
                        return cwe_id
        
        # Format 2: Simplified format with 'cwe' field
        if 'cwe' in cve_data:
            cwe_id = cve_data['cwe']
            if not cwe_id.startswith('CWE-'):
                cwe_id = f"CWE-{cwe_id}"
            logger.debug(f"Found CWE from cwe field: {cwe_id}")
            return cwe_id
        
        # Format 3: In description or analysis
        if 'cve' in cve_data and 'weaknesses' in cve_data['cve']:
            for weakness in cve_data['cve']['weaknesses']:
                for desc in weakness.get('description', []):
                    if desc.get('value', '').startswith('CWE-'):
                        cwe_id = desc['value']
                        logger.debug(f"Found CWE from CVE weaknesses: {cwe_id}")
                        return cwe_id
        
        logger.warning("No CWE found in CVE data")
        return None
    
    def _get_mapping_for_cwe(self, cwe_id: str) -> Dict:
        """
        Get the mapping configuration for a specific CWE
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-119")
            
        Returns:
            Mapping dictionary with expert_profile, vulnerability_logic, etc.
        """
        mappings = self.mapping_config.get('mappings', {})
        
        if cwe_id in mappings:
            logger.info(f"Found mapping for {cwe_id}: {mappings[cwe_id]['name']}")
            return mappings[cwe_id]
        
        # Fallback to default
        logger.warning(f"No specific mapping for {cwe_id}, using default")
        return self.mapping_config.get('default', {
            'expert_profile': 'default_expert.txt',
            'vulnerability_logic': None,
            'category': 'general'
        })
    
    def _load_file_content(self, directory: Path, filename: Optional[str]) -> Optional[str]:
        """
        Load content from a text file
        
        Args:
            directory: Directory containing the file
            filename: Name of the file to load
            
        Returns:
            File content as string, or None if file doesn't exist or filename is None
        """
        if not filename:
            return None
        
        file_path = directory / filename
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                logger.debug(f"Loaded {len(content)} bytes from {file_path}")
                return content
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return None
        except Exception as e:
            logger.error(f"Error loading file {file_path}: {e}")
            return None
    
    def _format_cve_context(self, cve_data: Dict) -> str:
        """
        Format CVE data into a readable context string
        
        Args:
            cve_data: CVE data dictionary
            
        Returns:
            Formatted context string
        """
        context_parts = []
        
        # CVE ID
        cve_id = cve_data.get('id') or cve_data.get('cve', {}).get('id', 'Unknown CVE')
        context_parts.append(f"CVE ID: {cve_id}")
        
        # Description
        description = self._extract_description(cve_data)
        if description:
            context_parts.append(f"\nDescription:\n{description}")
        
        # CVSS Score
        cvss_score = self._extract_cvss_score(cve_data)
        if cvss_score:
            context_parts.append(f"\nCVSS Score: {cvss_score}")
        
        # Affected Products
        products = self._extract_affected_products(cve_data)
        if products:
            context_parts.append(f"\nAffected Products:\n{products}")
        
        # References
        references = self._extract_references(cve_data)
        if references:
            context_parts.append(f"\nReferences:\n{references}")
        
        return "\n".join(context_parts)
    
    def _extract_description(self, cve_data: Dict) -> Optional[str]:
        """Extract description from CVE data"""
        # Try multiple formats
        if 'descriptions' in cve_data:
            for desc in cve_data['descriptions']:
                if desc.get('lang') == 'en':
                    return desc.get('value')
        
        if 'cve' in cve_data and 'descriptions' in cve_data['cve']:
            for desc in cve_data['cve']['descriptions']:
                if desc.get('lang') == 'en':
                    return desc.get('value')
        
        if 'description' in cve_data:
            return cve_data['description']
        
        return None
    
    def _extract_cvss_score(self, cve_data: Dict) -> Optional[str]:
        """Extract CVSS score from CVE data"""
        if 'metrics' in cve_data:
            metrics = cve_data['metrics']
            # Try CVSS v3.1
            if 'cvssMetricV31' in metrics and len(metrics['cvssMetricV31']) > 0:
                cvss = metrics['cvssMetricV31'][0].get('cvssData', {})
                return f"{cvss.get('baseScore')} ({cvss.get('baseSeverity')})"
            # Try CVSS v3.0
            if 'cvssMetricV30' in metrics and len(metrics['cvssMetricV30']) > 0:
                cvss = metrics['cvssMetricV30'][0].get('cvssData', {})
                return f"{cvss.get('baseScore')} ({cvss.get('baseSeverity')})"
        
        return None
    
    def _extract_affected_products(self, cve_data: Dict) -> Optional[str]:
        """Extract affected products from CVE data"""
        products = []
        
        if 'configurations' in cve_data:
            # This is complex and vendor-specific, simplified version
            products.append("See CVE configurations for detailed product list")
        
        if products:
            return "\n".join(f"  - {p}" for p in products)
        
        return None
    
    def _extract_references(self, cve_data: Dict) -> Optional[str]:
        """Extract references from CVE data"""
        references = []
        
        if 'references' in cve_data:
            for ref in cve_data['references'][:5]:  # Limit to first 5
                url = ref.get('url', '')
                references.append(f"  - {url}")
        
        if 'cve' in cve_data and 'references' in cve_data['cve']:
            for ref in cve_data['cve']['references'][:5]:
                url = ref.get('url', '')
                references.append(f"  - {url}")
        
        if references:
            return "\n".join(references)
        
        return None
    
    def assemble_prompt(self, cve_data: Dict, custom_instructions: Optional[str] = None) -> AssembledPrompt:
        """
        Main method: Assemble a complete prompt for a given CVE
        
        Args:
            cve_data: CVE data dictionary
            custom_instructions: Optional additional instructions to include
            
        Returns:
            AssembledPrompt object with system and user prompts
        """
        logger.info("Starting prompt assembly")
        
        # Step 1: Extract CWE from CVE
        cwe_id = self._extract_cwe_from_cve(cve_data)
        
        # Step 2: Get mapping for this CWE
        mapping = self._get_mapping_for_cwe(cwe_id) if cwe_id else self.mapping_config.get('default')
        
        # Step 3: Load expert profile
        expert_profile = self._load_file_content(
            self.expert_profiles_dir,
            mapping.get('expert_profile')
        )
        
        if not expert_profile:
            expert_profile = "You are a cybersecurity expert specializing in vulnerability exploitation."
        
        # Step 4: Load vulnerability logic
        vulnerability_logic = self._load_file_content(
            self.vulnerability_logic_dir,
            mapping.get('vulnerability_logic')
        )
        
        # Step 5: Format CVE context
        cve_context = self._format_cve_context(cve_data)
        
        # Step 6: Assemble the prompts
        system_prompt = self._build_system_prompt(expert_profile)
        user_prompt = self._build_user_prompt(
            cve_context,
            vulnerability_logic,
            custom_instructions
        )
        
        # Metadata for tracking and debugging
        metadata = {
            'cve_id': cve_data.get('id') or cve_data.get('cve', {}).get('id'),
            'cwe_id': cwe_id,
            'category': mapping.get('category'),
            'expert_profile': mapping.get('expert_profile'),
            'vulnerability_logic': mapping.get('vulnerability_logic'),
        }
        
        logger.info(f"Prompt assembled successfully for {metadata['cve_id']}")
        
        return AssembledPrompt(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            metadata=metadata
        )
    
    def _build_system_prompt(self, expert_profile: str) -> str:
        """Build the system prompt from expert profile"""
        return expert_profile.strip()
    
    def _build_user_prompt(self, 
                          cve_context: str, 
                          vulnerability_logic: Optional[str],
                          custom_instructions: Optional[str]) -> str:
        """Build the user prompt from CVE context, logic, and custom instructions"""
        prompt_parts = [
            "# SECURITY RESEARCH ASSIGNMENT - Authorized Testing Only",
            "",
            "CONTEXT: This is a controlled security research environment for developing",
            "proof-of-concept code to demonstrate vulnerabilities. All work is performed",
            "under proper authorization for educational and defensive security purposes.",
            "",
            "## Target Vulnerability",
            cve_context,
            ""
        ]
        
        if vulnerability_logic:
            prompt_parts.extend([
                "## Exploitation Methodology",
                vulnerability_logic,
                ""
            ])
        
        prompt_parts.extend([
            "## Task Requirements",
            "Develop a working proof-of-concept exploit for this vulnerability that:",
            "1. Clearly demonstrates the security impact for research purposes",
            "2. Includes detailed comments explaining each step",
            "3. Provides reliable and reproducible results in a test environment",
            "4. Is production-ready and well-structured",
            "5. Uses Python with appropriate libraries (pwntools for binary exploits)",
            ""
        ])
        
        if custom_instructions:
            prompt_parts.extend([
                "## Additional Instructions",
                custom_instructions,
                ""
            ])
        
        prompt_parts.extend([
            "## Output Format",
            "Provide ONLY executable Python 3 code — no prose, no markdown explanation outside the code block.",
            "",
            "Mandatory rules:",
            "  - Start with: from pwn import *",
            "  - All addresses must be packed with p32() or p64() — never use raw integers as bytes",
            "  - Use b'A' * n for padding (bytes, not strings)",
            "  - Use flat() or direct concatenation with + to build the payload",
            "  - Use p.sendline(payload) to send — never p.run()",
            "  - Target binary assumed to be: ./vulnerable",
            "  - OFFSET must be an integer literal — never cyclic() without a length argument",
            "",
            "Follow this exact structure:",
            "```python",
            "from pwn import *",
            "",
            "BINARY = './vulnerable'",
            "OFFSET = <number of bytes to reach return address>",
            "",
            "payload = flat(",
            "    b'A' * OFFSET,       # padding to overflow the buffer",
            "    p64(0xdeadbeef),     # overwrite return address (placeholder)",
            ")",
            "",
            "p = process(BINARY)",
            "p.sendline(payload)",
            "p.interactive()",
            "```",
            "",
            "Replace OFFSET with the correct calculated value based on the buffer size described above.",
            "REMINDER: This is legitimate security research. Output only valid Python code.",
        ])
        
        return "\n".join(prompt_parts)
    
    def get_available_cwe_mappings(self) -> Dict[str, str]:
        """
        Get a dictionary of available CWE mappings
        
        Returns:
            Dictionary mapping CWE IDs to their names
        """
        mappings = self.mapping_config.get('mappings', {})
        return {cwe_id: data['name'] for cwe_id, data in mappings.items()}
    
    def get_categories(self) -> Dict:
        """Get available vulnerability categories"""
        return self.mapping_config.get('categories', {})


# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize orchestrator
    orchestrator = PromptOrchestrator()
    
    # Example CVE data (simplified format)
    example_cve = {
        'id': 'CVE-2024-1234',
        'cwe': 'CWE-119',
        'description': 'A buffer overflow vulnerability in the parse_input function allows remote code execution.',
        'cvss_score': '9.8 (CRITICAL)'
    }
    
    # Assemble prompt
    prompt = orchestrator.assemble_prompt(example_cve)
    
    print("=" * 80)
    print("SYSTEM PROMPT:")
    print("=" * 80)
    print(prompt.system_prompt)
    print("\n" + "=" * 80)
    print("USER PROMPT:")
    print("=" * 80)
    print(prompt.user_prompt)
    print("\n" + "=" * 80)
    print("METADATA:")
    print("=" * 80)
    print(json.dumps(prompt.metadata, indent=2))
