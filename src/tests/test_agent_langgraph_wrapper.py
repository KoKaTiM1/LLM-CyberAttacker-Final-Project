import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.agent_langgraph_wrapper import AgentContext, CyberAttackAgentWrapper, WorkflowState


def test_check_connections_step_uses_inference_service(monkeypatch):
    class FakeInferenceService:
        def health_check(self):
            return True

    monkeypatch.setattr(
        "modules.agent_langgraph_wrapper.InferenceService",
        FakeInferenceService,
    )

    wrapper = CyberAttackAgentWrapper()
    context = AgentContext(file_path="dummy.c")

    result = wrapper.check_connections_step(context)

    assert result.connections_ok is True
    assert result.current_state == WorkflowState.CONNECTION_SUCCESS


def test_check_connections_step_reports_backend_failure(monkeypatch):
    class FakeInferenceService:
        def health_check(self):
            return False

    monkeypatch.setattr(
        "modules.agent_langgraph_wrapper.InferenceService",
        FakeInferenceService,
    )

    wrapper = CyberAttackAgentWrapper()
    context = AgentContext(file_path="dummy.c")

    result = wrapper.check_connections_step(context)

    assert result.connections_ok is False
    assert result.current_state == WorkflowState.CONNECTION_FAILED
    assert "configured inference backend" in (result.error_message or "")
