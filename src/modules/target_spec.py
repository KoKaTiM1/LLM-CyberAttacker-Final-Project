from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TargetSpec:
    """Normalized target contract consumed by sandbox backends."""

    mode: str
    target_type: str
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


def build_file_target_spec(file_path: str, docker_base_image: str = "gcc:latest") -> TargetSpec:
    is_c_file = file_path.lower().endswith(".c")
    container_target_path = "/tmp/target.c" if is_c_file else "/tmp/target.txt"

    return TargetSpec(
        mode="file",
        target_type="local_file",
        source_path=file_path,
        docker_base_image=docker_base_image,
        container_target_path=container_target_path,
        compile_command="gcc /tmp/target.c -o /tmp/target -fno-stack-protector -z execstack -no-pie"
        if is_c_file
        else None,
        run_command="/tmp/target" if is_c_file else None,
        build_strategy="use_existing_file",
        artifact_paths=[file_path],
        metadata={"source_language": "c" if is_c_file else "text"},
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
        cve_id=cve_id,
        cwe_id=cwe_id,
        docker_base_image=docker_base_image,
        build_strategy="needs_reproduction_plan",
        metadata=metadata or {},
    )
