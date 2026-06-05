import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.agent_langgraph_wrapper import (  # noqa: E402
    AgentContext,
    CyberAttackAgentWrapper,
    WorkflowState,
    _curated_cve_attack_script,
)


def test_extract_cpe_criteria_from_nested_nvd_shape():
    wrapper = CyberAttackAgentWrapper()
    cve_data = {
        "cve": {
            "configurations": [
                {
                    "nodes": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "criteria": "cpe:2.3:a:cimg:cimg:.220:*:*:*:*:*:*:*"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    }

    assert wrapper._extract_cpe_criteria(cve_data) == [
        "cpe:2.3:a:cimg:cimg:.220:*:*:*:*:*:*:*"
    ]


def test_plan_reproduction_uses_exact_cimg_version_builder():
    wrapper = CyberAttackAgentWrapper()
    context = AgentContext(cve_id="CVE-2018-7588")
    context.input_type = "cve"
    context.cve_target_info = {"version_hint": ".220", "missing_fields": []}

    context = wrapper.plan_reproduction_step(context)

    assert context.current_state == WorkflowState.REPRODUCTION_PLANNED
    assert context.reproduction_plan["executable_path"] == "/tmp/cimg_bmp_loader"
    setup_commands = context.reproduction_plan["setup_commands"]
    assert any("--branch v.220" in cmd for cmd in setup_commands)
    assert any("/opt/CImg/CImg.h" in cmd for cmd in setup_commands)


def test_curated_cimg_script_targets_real_poc_payload_names():
    script = _curated_cve_attack_script("CVE-2018-7588")

    assert "cimg-heap-overflow-load_bmp-48427" in script
    assert "cimg-heap-overflow-load_bmp-48457" in script
    assert 'if name.lower().endswith(".md")' in script
    assert "exploit successful" in script
