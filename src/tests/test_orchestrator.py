"""
Unit tests for the Prompt Orchestrator
"""

import json
import pytest
from pathlib import Path
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.orchestrator import PromptOrchestrator, AssembledPrompt


class TestPromptOrchestrator:
    """Test suite for PromptOrchestrator"""
    
    @pytest.fixture
    def orchestrator(self):
        """Create an orchestrator instance for testing"""
        return PromptOrchestrator()
    
    def test_initialization(self, orchestrator):
        """Test that orchestrator initializes correctly"""
        assert orchestrator is not None
        assert orchestrator.mapping_config is not None
        assert 'mappings' in orchestrator.mapping_config
        assert orchestrator.expert_profiles_dir.exists()
        assert orchestrator.vulnerability_logic_dir.exists()
    
    def test_load_mapping_config(self, orchestrator):
        """Test that mapping config loads correctly"""
        config = orchestrator.mapping_config
        
        assert 'mappings' in config
        assert 'default' in config
        assert 'categories' in config
        
        # Check some known mappings exist
        assert 'CWE-119' in config['mappings']
        assert 'CWE-89' in config['mappings']
        assert 'CWE-79' in config['mappings']
    
    def test_extract_cwe_simple_format(self, orchestrator):
        """Test CWE extraction from simple format"""
        cve_data = {
            'id': 'CVE-2024-1234',
            'cwe': 'CWE-119'
        }
        
        cwe = orchestrator._extract_cwe_from_cve(cve_data)
        assert cwe == 'CWE-119'
    
    def test_extract_cwe_nvd_format(self, orchestrator):
        """Test CWE extraction from NVD API format"""
        cve_data = {
            'id': 'CVE-2024-1234',
            'weaknesses': [
                {
                    'description': [
                        {'lang': 'en', 'value': 'CWE-89'}
                    ]
                }
            ]
        }
        
        cwe = orchestrator._extract_cwe_from_cve(cve_data)
        assert cwe == 'CWE-89'
    
    def test_extract_cwe_no_cwe(self, orchestrator):
        """Test CWE extraction when no CWE is present"""
        cve_data = {
            'id': 'CVE-2024-1234',
            'description': 'Some vulnerability'
        }
        
        cwe = orchestrator._extract_cwe_from_cve(cve_data)
        assert cwe is None
    
    def test_get_mapping_for_known_cwe(self, orchestrator):
        """Test getting mapping for a known CWE"""
        mapping = orchestrator._get_mapping_for_cwe('CWE-119')
        
        assert mapping is not None
        assert 'expert_profile' in mapping
        assert 'vulnerability_logic' in mapping
        assert mapping['name'] == 'Buffer Overflow'
        assert mapping['expert_profile'] == 'binary_exploitation.txt'
    
    def test_get_mapping_for_unknown_cwe(self, orchestrator):
        """Test getting mapping for an unknown CWE (should return default)"""
        mapping = orchestrator._get_mapping_for_cwe('CWE-99999')
        
        assert mapping is not None
        assert 'expert_profile' in mapping
        assert mapping['expert_profile'] == 'default_expert.txt'
    
    def test_load_expert_profile(self, orchestrator):
        """Test loading an expert profile file"""
        content = orchestrator._load_file_content(
            orchestrator.expert_profiles_dir,
            'binary_exploitation.txt'
        )
        
        assert content is not None
        assert len(content) > 0
        assert 'Binary Exploitation Expert' in content
    
    def test_load_vulnerability_logic(self, orchestrator):
        """Test loading a vulnerability logic file"""
        content = orchestrator._load_file_content(
            orchestrator.vulnerability_logic_dir,
            'buffer_overflow.txt'
        )
        
        assert content is not None
        assert len(content) > 0
        assert 'Buffer Overflow' in content
    
    def test_load_nonexistent_file(self, orchestrator):
        """Test loading a file that doesn't exist"""
        content = orchestrator._load_file_content(
            orchestrator.expert_profiles_dir,
            'nonexistent_file.txt'
        )
        
        assert content is None
    
    def test_format_cve_context(self, orchestrator):
        """Test formatting CVE data into context"""
        cve_data = {
            'id': 'CVE-2024-1234',
            'descriptions': [
                {'lang': 'en', 'value': 'A buffer overflow vulnerability'}
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
        
        context = orchestrator._format_cve_context(cve_data)
        
        assert 'CVE-2024-1234' in context
        assert 'buffer overflow' in context
        assert '9.8' in context
        assert 'CRITICAL' in context
    
    def test_assemble_prompt_buffer_overflow(self, orchestrator):
        """Test assembling a complete prompt for buffer overflow"""
        cve_data = {
            'id': 'CVE-2024-1234',
            'cwe': 'CWE-119',
            'description': 'A buffer overflow in parse_input allows RCE',
            'cvss_score': '9.8 (CRITICAL)'
        }
        
        prompt = orchestrator.assemble_prompt(cve_data)
        
        assert isinstance(prompt, AssembledPrompt)
        assert prompt.system_prompt is not None
        assert prompt.user_prompt is not None
        assert prompt.metadata is not None
        
        # Check system prompt contains expert profile
        assert 'Binary Exploitation Expert' in prompt.system_prompt
        
        # Check user prompt contains CVE context
        assert 'CVE-2024-1234' in prompt.user_prompt
        assert 'buffer overflow' in prompt.user_prompt.lower()
        
        # Check metadata
        assert prompt.metadata['cve_id'] == 'CVE-2024-1234'
        assert prompt.metadata['cwe_id'] == 'CWE-119'
    
    def test_assemble_prompt_sql_injection(self, orchestrator):
        """Test assembling a prompt for SQL injection"""
        cve_data = {
            'id': 'CVE-2024-5678',
            'cwe': 'CWE-89',
            'description': 'SQL injection in login form',
            'cvss_score': '8.5 (HIGH)'
        }
        
        prompt = orchestrator.assemble_prompt(cve_data)
        
        assert isinstance(prompt, AssembledPrompt)
        
        # Check system prompt contains web security expert
        assert 'Web Application Security Expert' in prompt.system_prompt
        
        # Check user prompt contains SQL injection methodology
        assert 'SQL Injection' in prompt.user_prompt
        
        # Check metadata
        assert prompt.metadata['cwe_id'] == 'CWE-89'
        assert prompt.metadata['category'] == 'injection'
    
    def test_assemble_prompt_with_custom_instructions(self, orchestrator):
        """Test assembling a prompt with custom instructions"""
        cve_data = {
            'id': 'CVE-2024-1234',
            'cwe': 'CWE-119',
            'description': 'Buffer overflow vulnerability'
        }
        
        custom = "Focus on Windows 10 x64 platform"
        
        prompt = orchestrator.assemble_prompt(cve_data, custom_instructions=custom)
        
        assert custom in prompt.user_prompt
    
    def test_assemble_prompt_no_cwe(self, orchestrator):
        """Test assembling a prompt when no CWE is found (should use default)"""
        cve_data = {
            'id': 'CVE-2024-9999',
            'description': 'Some unknown vulnerability'
        }
        
        prompt = orchestrator.assemble_prompt(cve_data)
        
        assert isinstance(prompt, AssembledPrompt)
        assert prompt.metadata['cwe_id'] is None
        
        # Should use default expert
        assert 'Cybersecurity Exploitation Expert' in prompt.system_prompt or \
               'expert' in prompt.system_prompt.lower()
    
    def test_get_available_cwe_mappings(self, orchestrator):
        """Test getting available CWE mappings"""
        mappings = orchestrator.get_available_cwe_mappings()
        
        assert isinstance(mappings, dict)
        assert len(mappings) > 0
        assert 'CWE-119' in mappings
        assert mappings['CWE-119'] == 'Buffer Overflow'
    
    def test_get_categories(self, orchestrator):
        """Test getting vulnerability categories"""
        categories = orchestrator.get_categories()
        
        assert isinstance(categories, dict)
        assert 'memory_corruption' in categories
        assert 'injection' in categories
        assert 'web_security' in categories


class TestPromptQuality:
    """Test the quality and completeness of assembled prompts"""
    
    @pytest.fixture
    def orchestrator(self):
        return PromptOrchestrator()
    
    def test_prompt_has_clear_structure(self, orchestrator):
        """Test that prompts have clear structure"""
        cve_data = {'id': 'CVE-2024-1234', 'cwe': 'CWE-119', 'description': 'Test'}
        prompt = orchestrator.assemble_prompt(cve_data)
        
        # System prompt should be non-empty
        assert len(prompt.system_prompt) > 100
        
        # User prompt should have sections
        assert '##' in prompt.user_prompt  # Markdown headers
        assert 'Task' in prompt.user_prompt or 'Vulnerability' in prompt.user_prompt
    
    def test_prompt_includes_exploitation_requirements(self, orchestrator):
        """Test that prompts include clear exploitation requirements"""
        cve_data = {'id': 'CVE-2024-1234', 'cwe': 'CWE-119', 'description': 'Test'}
        prompt = orchestrator.assemble_prompt(cve_data)
        
        user_prompt = prompt.user_prompt.lower()
        
        # Should mention code/exploit
        assert 'code' in user_prompt or 'exploit' in user_prompt
        
        # Should mention output format
        assert 'output' in user_prompt or 'format' in user_prompt


def test_example_usage():
    """Test the example usage from the main block"""
    orchestrator = PromptOrchestrator()
    
    example_cve = {
        'id': 'CVE-2024-1234',
        'cwe': 'CWE-119',
        'description': 'A buffer overflow vulnerability in the parse_input function allows remote code execution.',
        'cvss_score': '9.8 (CRITICAL)'
    }
    
    prompt = orchestrator.assemble_prompt(example_cve)
    
    assert prompt is not None
    assert len(prompt.system_prompt) > 0
    assert len(prompt.user_prompt) > 0
    assert prompt.metadata['cve_id'] == 'CVE-2024-1234'


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, '-v'])
