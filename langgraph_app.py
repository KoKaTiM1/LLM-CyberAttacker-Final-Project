"""
langgraph_app.py

Adapter file that exposes a compiled LangGraph graph as `agent`
so that LangGraph Server / LangGraph Studio can discover and run it.

You must set `agent` to your compiled graph object from
`src.modules.cyber_attack_graph`.
"""

from typing import Any

# Import your compiled graph from the module where you defined it.
# Adjust these imports to match your actual code.
# For example, if in `cyber_attack_graph.py` you have:
#     cyber_attack_app = graph.compile()
# then import that and assign it to `agent` below.
try:
    from src.modules.cyber_attack_graph import CYBER_ATTACK_GRAPH  # example name
except ImportError:
    # Fallback: try other common names. Adjust/remove as needed.
    try:
        from src.modules.cyber_attack_graph import cyber_attack_app as CYBER_ATTACK_GRAPH
    except ImportError:
        from src.modules.cyber_attack_graph import cyber_attack_graph as CYBER_ATTACK_GRAPH  # type: ignore


# This is the object LangGraph Server expects:
# a compiled StateGraph (result of graph_builder.compile()).
agent: Any = CYBER_ATTACK_GRAPH
