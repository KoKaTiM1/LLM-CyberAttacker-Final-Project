import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.agent_langgraph_wrapper import AgentContext, CyberAttackAgentWrapper  # noqa: E402
from modules.target_spec import classify_cve_target_family  # noqa: E402


def test_classify_php_runtime_target_family():
    info = classify_cve_target_family(
        description="Stack-based buffer overflow in PECL ZIP bundled with PHP 5.2.1.",
        primary_target={"target_type": "a", "vendor": "php", "product": "php", "version": "5.2.1"},
        references=["http://www.php-security.org/MOPB/MOPB-16-2007.html"],
    )

    assert info["target_family"] == "language_runtime"
    assert info["image_strategy"] == "runtime_image"
    assert info["docker_base_image"] == "php:8.2-cli"


def test_classify_kernel_target_family():
    info = classify_cve_target_family(
        description="An out-of-bounds write in the Linux kernel tcp_v6_syn_recv_sock function.",
        primary_target={"target_type": "o", "vendor": "linux", "product": "linux_kernel", "version": "4.13"},
        references=[],
    )

    assert info["target_family"] == "kernel_level"
    assert info["image_strategy"] == "requires_kernel_environment"


def test_kernel_targets_stop_as_unresolved_for_docker():
    wrapper = CyberAttackAgentWrapper()
    context = AgentContext(cve_id="CVE-2018-5703")
    context.input_type = "cve"
    context.cve_target_info = {
        "target_family": "kernel_level",
        "image_strategy": "requires_kernel_environment",
        "docker_base_image": "debian:bookworm-slim",
        "missing_fields": [],
    }

    context = wrapper.plan_reproduction_step(context)

    assert context.reproduction_plan["reason"] == "requires_kernel_environment"
    assert context.reproduction_plan["target_family"] == "kernel_level"


def test_build_target_artifact_uses_selected_runtime_image():
    wrapper = CyberAttackAgentWrapper()
    context = AgentContext(cve_id="CVE-2007-1399")
    context.input_type = "cve"
    context.cwe_id = "CWE-119"
    context.cve_target_info = {}
    context.reproduction_plan = {
        "strategy": "system_package_tool",
        "tool_name": "php",
        "executable_path": "/usr/local/bin/php",
        "target_family": "language_runtime",
        "image_strategy": "runtime_image",
        "docker_base_image": "php:8.2-cli",
        "setup_commands": ["php -v"],
    }

    context = wrapper.build_target_artifact_step(context)

    assert context.target_spec["docker_base_image"] == "php:8.2-cli"
    assert context.target_spec["target_family"] == "language_runtime"
    assert context.target_spec["image_strategy"] == "runtime_image"


def test_generic_system_package_tool_plan_for_wildmidi():
    wrapper = CyberAttackAgentWrapper()
    context = AgentContext(cve_id="CVE-2017-1000418")
    context.input_type = "cve"
    context.cve_target_info = {
        "product_hint": "wildmidi",
        "vendor_hint": "mindwerks",
        "description": "The WildMidi_Open function in WildMIDI allows remote attackers to cause a heap-based buffer overflow via a crafted file.",
        "references": ["https://github.com/Mindwerks/wildmidi/issues/178"],
        "target_family": "media_stack",
        "image_strategy": "package_image",
        "docker_base_image": "debian:bookworm-slim",
        "missing_fields": [],
    }

    context = wrapper.plan_reproduction_step(context)

    assert context.reproduction_plan["strategy"] == "system_package_tool"
    assert context.reproduction_plan["tool_name"] == "wildmidi"
    assert context.reproduction_plan["docker_base_image"] == "debian:bookworm-slim"


def test_generic_media_stack_plan_for_imagemagick():
    wrapper = CyberAttackAgentWrapper()
    context = AgentContext(cve_id="CVE-2018-5248")
    context.input_type = "cve"
    context.cve_target_info = {
        "product_hint": "imagemagick",
        "vendor_hint": "imagemagick",
        "description": "In ImageMagick there is a heap-based buffer over-read in the sixel decoder.",
        "references": ["https://github.com/ImageMagick/ImageMagick/issues/927"],
        "target_family": "media_stack",
        "image_strategy": "package_image",
        "docker_base_image": "debian:bookworm-slim",
        "missing_fields": [],
    }

    context = wrapper.plan_reproduction_step(context)

    assert context.reproduction_plan["strategy"] == "system_package_tool"
    assert context.reproduction_plan["tool_name"] == "imagemagick"
    assert context.reproduction_plan["executable_path"] == "/usr/bin/convert"


def test_generic_language_runtime_plan_for_php():
    wrapper = CyberAttackAgentWrapper()
    context = AgentContext(cve_id="CVE-2007-1399")
    context.input_type = "cve"
    context.cve_target_info = {
        "product_hint": "php",
        "vendor_hint": "php",
        "description": "Stack-based buffer overflow in the zip:// URL wrapper in PECL ZIP bundled with PHP.",
        "references": ["http://www.php-security.org/MOPB/MOPB-16-2007.html"],
        "target_family": "language_runtime",
        "image_strategy": "runtime_image",
        "docker_base_image": "php:8.2-cli",
        "missing_fields": [],
    }

    context = wrapper.plan_reproduction_step(context)

    assert context.reproduction_plan["strategy"] == "system_package_tool"
    assert context.reproduction_plan["docker_base_image"] == "php:8.2-cli"
    assert context.reproduction_plan["tool_name"] == "php"
