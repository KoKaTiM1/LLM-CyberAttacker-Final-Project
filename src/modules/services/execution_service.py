from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from ..sandbox import SandboxManager


@dataclass
class ExecutionServiceResult:
    success: bool = False
    sandbox_result: str = ""
    error_message: str = ""
    log_messages: list[str] = field(default_factory=list)


class ExecutionInfrastructureError(RuntimeError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}


class ExecutionService:
    """Local sandbox execution service. Docker stays local in this phase."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path(__file__).parent.parent.parent / "config" / "sandbox_config.json"

    def execute(
        self,
        *,
        attack_script: str,
        target_spec: Dict[str, Any],
        vulnerability_data: Dict[str, Any],
    ) -> ExecutionServiceResult:
        if target_spec and target_spec.get("target_type") == "unresolved_cve":
            return ExecutionServiceResult(
                success=False,
                sandbox_result=json.dumps(
                    {
                        "status": "unresolved_cve",
                        "message": "Skipping sandbox execution because no reproducible target is available",
                        "target_spec": target_spec,
                    },
                    indent=2,
                ),
                log_messages=["Skipping sandbox execution: unresolved CVE target"],
            )

        if not attack_script:
            return self._infra_failure("No attack script available for execution")

        logs = [f"Attack script ready ({len(attack_script)} characters)"]
        if target_spec:
            logs.append(f"Using target spec: {target_spec.get('target_type')}")

        if not self.config_path.exists():
            return self._infra_failure(f"Sandbox config file not found: {self.config_path}")

        sandbox_manager = SandboxManager(config_file=str(self.config_path))
        sandbox_manager.environments = {
            name: env
            for name, env in sandbox_manager.environments.items()
            if name == "Docker_Container"
        }

        target_type = (target_spec or {}).get("target_type")
        docker_env = sandbox_manager.environments.get("Docker_Container")
        if docker_env and target_spec:
            selected_image = target_spec.get("docker_base_image")
            if selected_image:
                docker_env.image = selected_image
                logs.append(f"Using Docker image: {selected_image}")

        if target_type == "cve_system_binary":
            setup_commands = (target_spec.get("metadata") or {}).get("setup_commands", [])
            if docker_env and setup_commands:
                docker_env.setup_commands = setup_commands

        if not sandbox_manager.environments:
            return self._infra_failure("Docker sandbox environment is not enabled in config")

        enabled_envs = list(sandbox_manager.environments.keys())
        logs.append(f"Loaded {len(enabled_envs)} environment(s): {', '.join(enabled_envs)}")
        logs.append("Connecting to sandbox environments...")

        if not sandbox_manager.connect_all():
            return self._infra_failure("Failed to connect to any sandbox environment")

        logs.append("Connected to sandbox environments")
        try:
            logs.append("Running basic test on all environments...")
            test_results = sandbox_manager.run_test_on_all("print('Sandbox test successful')")
            successful_tests = [name for name, result in test_results.items() if result.success]
            failed_tests = [name for name, result in test_results.items() if not result.success]

            if not successful_tests:
                details = {
                    env_name: {
                        "success": result.success,
                        "output": getattr(result, "output", ""),
                        "error": getattr(result, "error", ""),
                    }
                    for env_name, result in test_results.items()
                }
                return self._infra_failure(
                    f"All test runs failed. Failed environments: {', '.join(failed_tests)}",
                    details,
                )

            logs.append(f"Test passed in {len(successful_tests)} environment(s)")
            if failed_tests:
                logs.append(f"Test failed in: {', '.join(failed_tests)}")

            logs.append("Executing attack script...")
            try:
                results = self._execute_attack(
                    sandbox_manager=sandbox_manager,
                    attack_script=attack_script,
                    target_spec=target_spec,
                    vulnerability_data=vulnerability_data,
                )
            except ExecutionInfrastructureError as exc:
                return self._infra_failure(str(exc), exc.details, logs)

            sandbox_result = json.dumps(results, indent=2)

            successful_envs = []
            failed_envs = []
            for env_name, result in results.items():
                analysis = result.get("exploitation_analysis", {})
                if analysis.get("exploitation_successful", False):
                    successful_envs.append(env_name)
                    logs.append(f"{env_name}: Attack successful")
                else:
                    failed_envs.append(env_name)
                    logs.append(f"{env_name}: Attack failed")

            if successful_envs:
                logs.append(f"Attack succeeded in {len(successful_envs)} environment(s): {', '.join(successful_envs)}")
                return ExecutionServiceResult(success=True, sandbox_result=sandbox_result, log_messages=logs)

            logs.append(f"Attack failed in all {len(failed_envs)} environment(s)")
            return ExecutionServiceResult(success=False, sandbox_result=sandbox_result, log_messages=logs)
        finally:
            sandbox_manager.disconnect_all()
            logs.append("Sandbox cleanup completed")

    @staticmethod
    def _execute_attack(
        *,
        sandbox_manager: SandboxManager,
        attack_script: str,
        target_spec: Dict[str, Any],
        vulnerability_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        target_type = (target_spec or {}).get("target_type")
        if target_type == "local_file":
            source_path = target_spec.get("source_path")
            remote_path = target_spec.get("container_target_path") or "/tmp/target"
            upload_results = sandbox_manager.upload_vulnerable_file(source_path, remote_path)
            if not any(upload_results.values()):
                raise ExecutionInfrastructureError(
                    "Failed to stage target file in sandbox",
                    {"upload_results": upload_results, "remote_path": remote_path},
                )

            script_type = "c" if str(attack_script).lstrip().startswith("#include") else "python"
            target_result = sandbox_manager.generate_and_execute_attack(
                vulnerable_file_path=remote_path,
                attack_script=attack_script,
                script_type=script_type,
                vulnerability_data=vulnerability_data,
            )
            environment_results = target_result.get("environment_results", {})
            return {
                env_name: {
                    "success": env_result.get("success", False),
                    "execution_time": env_result.get("execution_time", 0),
                    "output": env_result.get("output", ""),
                    "error": env_result.get("error"),
                    "exploitation_analysis": env_result.get("analysis", {}),
                }
                for env_name, env_result in environment_results.items()
            }

        return sandbox_manager.execute_exploit(
            exploit_script=attack_script,
            vulnerability_data=vulnerability_data,
        )

    @staticmethod
    def _infra_failure(
        message: str,
        details: Optional[Dict[str, Any]] = None,
        log_messages: Optional[list[str]] = None,
    ) -> ExecutionServiceResult:
        payload = {
            "status": "infrastructure_error",
            "message": message,
            "details": details or {},
        }
        return ExecutionServiceResult(
            success=False,
            sandbox_result=json.dumps({"infrastructure": payload}, indent=2),
            error_message=message,
            log_messages=log_messages or [],
        )
