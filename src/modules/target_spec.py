from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TargetSpec:
    """Normalized target contract consumed by sandbox backends."""

    mode: str
    target_type: str
    target_family: str = "local_c_source"
    image_strategy: str = "compiler_image"
    source_path: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    docker_base_image: str = "gcc:latest"
    docker_image_tag: Optional[str] = None
    docker_context_path: Optional[str] = None
    container_target_path: str = "/tmp/target"
    compile_command: Optional[str] = None
    run_command: Optional[str] = None
    build_strategy: str = "use_existing_file"
    os_hint: Optional[str] = None
    version_hint: Optional[str] = None
    artifact_paths: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _detect_source_language(file_path: str, file_content: Optional[str] = None) -> str:
    normalized_path = file_path.lower()
    if normalized_path.endswith((".c", ".h")):
        return "c"

    if not file_content:
        return "text"

    content = file_content.strip()
    if not content:
        return "text"

    c_markers = [
        "#include",
        "int main(",
        "void main(",
        "printf(",
        "scanf(",
        "strcpy(",
        "strlen(",
        "char ",
        "return ",
    ]
    score = sum(1 for marker in c_markers if marker in content)
    if score >= 2 and "{" in content and "}" in content and ";" in content:
        return "c"

    return "text"


def build_file_target_spec(
    file_path: str,
    docker_base_image: str = "gcc:latest",
    file_content: Optional[str] = None,
) -> TargetSpec:
    source_language = _detect_source_language(file_path, file_content)
    is_c_file = source_language == "c"
    container_target_path = "/tmp/target.c" if is_c_file else "/tmp/target.txt"

    return TargetSpec(
        mode="file",
        target_type="local_file",
        target_family="local_c_source",
        image_strategy="compiler_image",
        source_path=file_path,
        docker_base_image=docker_base_image,
        container_target_path=container_target_path,
        compile_command="gcc /tmp/target.c -o /tmp/target -fno-stack-protector -z execstack -no-pie"
        if is_c_file
        else None,
        run_command="/tmp/target" if is_c_file else None,
        build_strategy="use_existing_file",
        artifact_paths=[file_path],
        metadata={
            "source_language": source_language,
            "source_filename": file_path,
        },
    )


def build_unresolved_cve_target_spec(
    *,
    cve_id: str,
    cwe_id: Optional[str],
    docker_base_image: str = "gcc:latest",
    metadata: Optional[Dict[str, Any]] = None,
) -> TargetSpec:
    return TargetSpec(
        mode="cve",
        target_type="unresolved_cve",
        target_family=(metadata or {}).get("target_family", "unresolved"),
        image_strategy=(metadata or {}).get("image_strategy", "unresolved"),
        cve_id=cve_id,
        cwe_id=cwe_id,
        docker_base_image=docker_base_image,
        build_strategy="needs_reproduction_plan",
        metadata=metadata or {},
    )


def build_cve_tool_target_spec(
    *,
    cve_id: str,
    cwe_id: Optional[str],
    tool_name: str,
    executable_path: str,
    target_family: str = "system_package_tool",
    image_strategy: str = "package_image",
    docker_base_image: str = "gcc:latest",
    setup_commands: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> TargetSpec:
    return TargetSpec(
        mode="cve",
        target_type="cve_system_binary",
        target_family=target_family,
        image_strategy=image_strategy,
        cve_id=cve_id,
        cwe_id=cwe_id,
        docker_base_image=docker_base_image,
        container_target_path=executable_path,
        run_command=executable_path,
        build_strategy="run_system_binary_exploit",
        artifact_paths=[],
        metadata={
            "tool_name": tool_name,
            "executable_path": executable_path,
            "setup_commands": setup_commands or [],
            **(metadata or {}),
        },
    )


def classify_cve_target_family(
    *,
    description: str,
    primary_target: Optional[Dict[str, Any]],
    references: Optional[List[str]] = None,
) -> Dict[str, str]:
    """Infer the broad target family and default Docker image strategy."""

    description_lower = (description or "").lower()
    refs_lower = " ".join(references or []).lower()
    target_type = (primary_target or {}).get("target_type") or ""
    vendor = ((primary_target or {}).get("vendor") or "").lower()
    product = ((primary_target or {}).get("product") or "").lower()

    kernel_markers = [
        "linux kernel",
        "kernel driver",
        "kernel ",
        "tcp_v6_syn_recv_sock",
        "net/ipv6/",
        "android for msm",
        "with all android releases from caf using the linux kernel",
    ]
    if target_type == "o" or any(marker in description_lower for marker in kernel_markers):
        return {
            "target_family": "kernel_level",
            "image_strategy": "requires_kernel_environment",
            "docker_base_image": "debian:bookworm-slim",
        }

    runtime_products = {"php", "php_zip", "pierrejoye"}
    if product in runtime_products or vendor in runtime_products or "php" in description_lower or "php" in refs_lower:
        return {
            "target_family": "language_runtime",
            "image_strategy": "runtime_image",
            "docker_base_image": "php:8.2-cli",
        }

    media_products = {"imagemagick", "libfpx", "ffmpeg", "wildmidi", "cimg"}
    if (
        product in media_products
        or vendor in media_products
        or any(name in description_lower for name in media_products)
        or any(name in refs_lower for name in media_products)
    ):
        return {
            "target_family": "media_stack",
            "image_strategy": "package_image",
            "docker_base_image": "debian:bookworm-slim",
        }

    if target_type == "a":
        return {
            "target_family": "system_package_tool",
            "image_strategy": "package_image",
            "docker_base_image": "debian:bookworm-slim",
        }

    return {
        "target_family": "unresolved",
        "image_strategy": "unresolved",
        "docker_base_image": "debian:bookworm-slim",
    }
