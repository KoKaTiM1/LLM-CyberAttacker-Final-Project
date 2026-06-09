import os
import sys
from pathlib import Path


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.inference_provider import InferenceResult
from modules.services import ExecutionService, InferenceService, RagService


class FakeProvider:
    def health_check(self):
        return True

    def generate(self, *, prompt, system="", model=None, stage="generation", temperature=0):
        return InferenceResult(
            text=f"{stage}:{model}:{prompt}",
            model=model or "fake-model",
            metrics={"stage": stage, "model": model or "fake-model"},
            raw={},
        )


def test_inference_service_routes_main_and_rag_calls():
    service = InferenceService(provider=FakeProvider())

    main = service.generate_main(prompt="main prompt", model="main-model", stage="main_stage")
    rag = service.generate_rag(prompt="rag prompt", model="rag-model", stage="rag_stage")

    assert main.text == "main_stage:main-model:main prompt"
    assert rag.text == "rag_stage:rag-model:rag prompt"


def test_rag_service_returns_original_input_when_index_missing(tmp_path):
    result = RagService(project_root=tmp_path).enrich(
        input_type="file",
        file_content="int main() { return 0; }",
    )

    assert result.file_content == "int main() { return 0; }"
    assert result.rag_context == ""
    assert result.log_messages


def test_execution_service_short_circuits_unresolved_cve():
    result = ExecutionService(config_path=Path("missing.json")).execute(
        attack_script="print('unused')",
        target_spec={"target_type": "unresolved_cve"},
        vulnerability_data={},
    )

    assert result.success is False
    assert "unresolved_cve" in result.sandbox_result
    assert "Skipping sandbox execution" in result.log_messages[0]


def test_execution_service_reports_file_staging_as_infrastructure_error(tmp_path, monkeypatch):
    config_path = tmp_path / "sandbox_config.json"
    config_path.write_text("{}", encoding="utf-8")

    class FakeDockerEnv:
        image = ""
        setup_commands = []

    class FakeTestResult:
        success = True
        output = "ok"
        error = ""

    class FakeSandboxManager:
        def __init__(self, config_file):
            self.environments = {"Docker_Container": FakeDockerEnv()}

        def connect_all(self):
            return True

        def run_test_on_all(self, test_script):
            return {"Docker_Container": FakeTestResult()}

        def upload_vulnerable_file(self, source_path, remote_path):
            return {"Docker_Container": False}

        def disconnect_all(self):
            return None

    monkeypatch.setattr(
        "modules.services.execution_service.SandboxManager",
        FakeSandboxManager,
    )

    result = ExecutionService(config_path=config_path).execute(
        attack_script="#include <stdio.h>\nint main(){return 0;}",
        target_spec={
            "target_type": "local_file",
            "source_path": "missing.c",
            "container_target_path": "/tmp/target.c",
        },
        vulnerability_data={},
    )

    assert result.success is False
    assert result.error_message == "Failed to stage target file in sandbox"
    assert "infrastructure_error" in result.sandbox_result
    assert "Sandbox cleanup completed" in result.log_messages
