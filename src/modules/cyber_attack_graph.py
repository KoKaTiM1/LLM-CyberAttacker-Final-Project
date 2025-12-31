from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

# TypedDict must come from typing_extensions on Python < 3.12
try:
    from typing_extensions import TypedDict
except ImportError:  # For Python >= 3.12
    from typing import TypedDict  # type: ignore

from langgraph.graph import StateGraph, START, END

# This is your OO "agent" and context
from .agent_langgraph_wrapper import (
    CyberAttackAgentWrapper,
    AgentContext,
    WorkflowState,
)


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


# ---------------------------------------------------------------------------
# Shared LangGraph state (mirrors AgentContext)
# ---------------------------------------------------------------------------

class CyberState(TypedDict, total=False):
    """
    Shared state for the LangGraph cyber-attack workflow.

    This mirrors the AgentContext fields so that:

    * CyberAttackAgentWrapper remains the single source of business logic.
    * LangGraph only controls the ordering and visualization of steps.
    """

    # Input / basic fields
    file_path: str
    file_content: str

    # Analysis / exploitation artefacts
    vulnerability_data: Dict[str, Any]
    llm_response: str
    attack_script: str
    sandbox_result: str
    attack_result: str

    # Status flags
    connections_ok: bool
    error_message: str
    current_state: str  # WorkflowState.value

    # Logs
    execution_log: List[str]
    logs: List[str]     # alias for compatibility


# Single shared wrapper instance – stateless step methods
_wrapper = CyberAttackAgentWrapper()


# ---------------------------------------------------------------------------
# Conversion helpers: CyberState <-> AgentContext
# ---------------------------------------------------------------------------

def _context_from_state(state: CyberState) -> AgentContext:
    """
    Build an AgentContext from the plain dict state used by LangGraph.

    This allows the wrapper (OO layer) to stay the owner of all logic,
    while LangGraph works with simple, serializable data.
    """
    file_path = state.get("file_path") or ""
    ctx = AgentContext(file_path)

    # Copy simple data fields
    ctx.file_content = state.get("file_content", "")
    ctx.vulnerability_data = state.get("vulnerability_data", {})
    ctx.llm_response = state.get("llm_response", "")
    ctx.attack_script = state.get("attack_script", "")
    ctx.sandbox_result = state.get("sandbox_result", "")
    ctx.attack_result = state.get("attack_result", "")
    ctx.connections_ok = state.get("connections_ok", False)
    ctx.error_message = state.get("error_message", "")

    # Logs: prefer execution_log, then logs
    logs = state.get("execution_log") or state.get("logs") or []
    ctx.execution_log = list(logs)

    # Workflow state
    current_state = state.get("current_state")
    if current_state:
        try:
            ctx.current_state = WorkflowState(current_state)
        except ValueError:
            ctx.current_state = WorkflowState.INITIALIZED

    return ctx


def _state_from_context(ctx: AgentContext) -> CyberState:
    """
    Convert AgentContext back into CyberState for LangGraph.

    Note: we write both `execution_log` and `logs` for compatibility
    with existing tests or consumers that expect `logs`.
    """
    logs = list(getattr(ctx, "execution_log", []))

    return {
        "file_path": str(getattr(ctx, "file_path", "")),
        "file_content": getattr(ctx, "file_content", ""),
        "vulnerability_data": getattr(ctx, "vulnerability_data", {}),
        "llm_response": getattr(ctx, "llm_response", ""),
        "attack_script": getattr(ctx, "attack_script", ""),
        "sandbox_result": getattr(ctx, "sandbox_result", ""),
        "attack_result": getattr(ctx, "attack_result", ""),
        "connections_ok": getattr(ctx, "connections_ok", False),
        "error_message": getattr(ctx, "error_message", ""),
        "current_state": getattr(
            getattr(ctx, "current_state", WorkflowState.INITIALIZED),
            "value",
            WorkflowState.INITIALIZED.value,
        ),
        "execution_log": logs,
        "logs": logs,
    }


def _has_error(state: CyberState) -> bool:
    """
    Determine if the current state carries an error.
    """
    return bool(state.get("error_message"))


# ---------------------------------------------------------------------------
# LangGraph node implementations (thin wrappers around the agent)
# ---------------------------------------------------------------------------

def check_connections_node(state: CyberState) -> CyberState:
    """
    Node 1 – delegate to wrapper.check_connections_step.
    """
    ctx = _context_from_state(state)
    ctx = _wrapper.check_connections_step(ctx)
    logger.info("check_connections_node executed, state=%s", ctx.current_state.value)
    return _state_from_context(ctx)


def validate_file_node(state: CyberState) -> CyberState:
    """
    Node 2 – delegate to wrapper.validate_file_step.
    """
    ctx = _context_from_state(state)
    ctx = _wrapper.validate_file_step(ctx)
    logger.info("validate_file_node executed, state=%s", ctx.current_state.value)
    return _state_from_context(ctx)


def analyze_vulnerability_node(state: CyberState) -> CyberState:
    """
    Node 3 – delegate to wrapper.analyze_vulnerability_step.
    """
    ctx = _context_from_state(state)
    ctx = _wrapper.analyze_vulnerability_step(ctx)
    logger.info("analyze_vulnerability_node executed, state=%s", ctx.current_state.value)
    return _state_from_context(ctx)


def create_attack_script_node(state: CyberState) -> CyberState:
    """
    Node 4 – delegate to wrapper.create_attack_script_step.
    """
    ctx = _context_from_state(state)
    ctx = _wrapper.create_attack_script_step(ctx)
    logger.info("create_attack_script_node executed, state=%s", ctx.current_state.value)
    return _state_from_context(ctx)


def execute_in_sandbox_node(state: CyberState) -> CyberState:
    """
    Node 5 – delegate to wrapper.execute_in_sandbox_step.
    """
    ctx = _context_from_state(state)
    ctx = _wrapper.execute_in_sandbox_step(ctx)
    logger.info("execute_in_sandbox_node executed, state=%s", ctx.current_state.value)
    return _state_from_context(ctx)


def handle_error_node(state: CyberState) -> CyberState:
    """
    Node used as a sink for errors from any previous step.

    Keeps behavior consistent with the wrapper by logging via the context.
    """
    ctx = _context_from_state(state)
    msg = ctx.error_message or "Unknown error"
    ctx.log_step(f"Handling error: {msg}")
    logger.error("Workflow error: %s", msg)
    return _state_from_context(ctx)


def workflow_complete_node(state: CyberState) -> CyberState:
    """
    Final node – marks logical completion of the workflow.
    """
    ctx = _context_from_state(state)
    ctx.log_step("Workflow completed")
    logger.info(
        "workflow_complete_node executed, final_state=%s",
        ctx.current_state.value,
    )
    return _state_from_context(ctx)


# ---------------------------------------------------------------------------
# Routing / conditional edges – based only on error presence
# ---------------------------------------------------------------------------

def route_after_check_connections(state: CyberState) -> str:
    """
    Router after check_connections_node.
    """
    return "handle_error" if _has_error(state) else "validate_file"


def route_after_validate_file(state: CyberState) -> str:
    """
    Router after validate_file_node.
    """
    return "handle_error" if _has_error(state) else "analyze_vulnerability"


def route_after_analyze(state: CyberState) -> str:
    """
    Router after analyze_vulnerability_node.
    """
    return "handle_error" if _has_error(state) else "create_attack_script"


def route_after_create_script(state: CyberState) -> str:
    """
    Router after create_attack_script_node.
    """
    return "handle_error" if _has_error(state) else "execute_in_sandbox"


def route_after_sandbox(state: CyberState) -> str:
    """
    Router after execute_in_sandbox_node.
    """
    return "handle_error" if _has_error(state) else "workflow_complete"


# ---------------------------------------------------------------------------
# Graph builder and compiled app
# ---------------------------------------------------------------------------

def build_cyber_attack_graph():
    """
    Build and compile the LangGraph graph for the cyber-attack workflow.

    The nodes themselves are thin adapters:

    * Convert CyberState -> AgentContext
    * Call the appropriate step on CyberAttackAgentWrapper
    * Convert AgentContext -> CyberState

    This keeps CyberAttackAgentWrapper as the "active agent" abstraction,
    and LangGraph only as the visual / orchestration layer.
    """
    workflow = StateGraph(CyberState)

    # Nodes
    workflow.add_node("check_connections", check_connections_node)
    workflow.add_node("validate_file", validate_file_node)
    workflow.add_node("analyze_vulnerability", analyze_vulnerability_node)
    workflow.add_node("create_attack_script", create_attack_script_node)
    workflow.add_node("execute_in_sandbox", execute_in_sandbox_node)
    workflow.add_node("handle_error", handle_error_node)
    workflow.add_node("workflow_complete", workflow_complete_node)

    # Start / end
    workflow.add_edge(START, "check_connections")
    workflow.add_edge("workflow_complete", END)
    workflow.add_edge("handle_error", END)

    # Conditional routing based on presence of error_message
    workflow.add_conditional_edges(
        "check_connections",
        route_after_check_connections,
        ["validate_file", "handle_error"],
    )
    workflow.add_conditional_edges(
        "validate_file",
        route_after_validate_file,
        ["analyze_vulnerability", "handle_error"],
    )
    workflow.add_conditional_edges(
        "analyze_vulnerability",
        route_after_analyze,
        ["create_attack_script", "handle_error"],
    )
    workflow.add_conditional_edges(
        "create_attack_script",
        route_after_create_script,
        ["execute_in_sandbox", "handle_error"],
    )
    workflow.add_conditional_edges(
        "execute_in_sandbox",
        route_after_sandbox,
        ["workflow_complete", "handle_error"],
    )

    return workflow.compile()


# Compiled graph exposed as the LangGraph "agent"
cyber_attack_app = build_cyber_attack_graph()


# ---------------------------------------------------------------------------
# Convenience helpers (single file, folder, visualization)
# ---------------------------------------------------------------------------

def run_cyber_attack(file_path: str) -> CyberState:
    """
    Convenience wrapper to run the whole LangGraph workflow on a single file.

    The initial state contains only the file_path (and an empty log list),
    all other fields are filled by the wrapper steps.
    """
    initial_state: CyberState = {
        "file_path": str(file_path),
        "execution_log": [],
        "logs": [],
    }
    result: CyberState = cyber_attack_app.invoke(initial_state)
    return result


def run_cyber_attack_on_folder(
    folder_path: str,
    allowed_suffixes: Optional[List[str]] = None,
) -> Dict[str, CyberState]:
    """
    Run the workflow on all files in a given folder (.c/.txt by default).

    This is implemented outside the graph so that:
    * The graph stays focused on "single file" logic.
    * Batch processing can be reused from tests or scripts.
    """
    folder = Path(folder_path)
    if not folder.exists() or not folder.is_dir():
        raise ValueError(f"Folder does not exist or is not a directory: {folder}")

    if allowed_suffixes is None:
        allowed_suffixes = [".c", ".txt"]

    results: Dict[str, CyberState] = {}

    for entry in sorted(folder.iterdir()):
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in (s.lower() for s in allowed_suffixes):
            continue

        state = run_cyber_attack(str(entry))
        results[entry.name] = state

    return results


def show_graph_png() -> bytes:
    """
    Render the workflow as a PNG (Mermaid) and return raw bytes.

    Used by tests or ad-hoc visualization.
    """
    graph = cyber_attack_app.get_graph(xray=True)
    return graph.draw_mermaid_png()


# ---------------------------------------------------------------------------
# CLI entry point (optional)
# ---------------------------------------------------------------------------

def main() -> None:
    """
    CLI helper:

    * Saves the graph diagram as a PNG.
    * Optionally runs the workflow on a single file (--file).
    * Optionally runs the workflow on all files in a folder (--folder).
    """
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Cyber-attack LangGraph workflow")
    parser.add_argument(
        "--out",
        default="cyber_attack_graph.png",
        help="Output PNG path for the graph diagram",
    )
    parser.add_argument(
        "--file",
        help="Optional C/TXT file to run the workflow on",
    )
    parser.add_argument(
        "--folder",
        help="Optional folder containing multiple files to process",
    )
    args = parser.parse_args()

    # Always refresh the PNG so it stays in sync with the code
    png_bytes = show_graph_png()
    out_path = Path(args.out)
    out_path.write_bytes(png_bytes)
    print(f"Saved graph diagram to: {out_path}")

    # Run on a single file if requested
    if args.file:
        print(f"\n=== Running workflow on single file: {args.file} ===")
        state = run_cyber_attack(args.file)
        print("Final state:")
        print(json.dumps(state, indent=2, default=str))

    # Run on all files in a folder if requested
    if args.folder:
        print(f"\n=== Running workflow on all files in folder: {args.folder} ===")
        batch = run_cyber_attack_on_folder(args.folder)
        for name, state in batch.items():
            error = state.get("error_message")
            success = not bool(error)
            print(f"\n[{name}]")
            print(f"  Success:       {success}")
            print(f"  Error message: {error or 'None'}")


if __name__ == "__main__":
    main()
