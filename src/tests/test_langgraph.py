#!/usr/bin/env python3
"""
Test script for the LangGraph cyber-attack workflow.

This script:
1. Adds the project root to sys.path so we can import src.modules.*.
2. Builds an absolute path to the test file (independent of CWD).
3. Runs the LangGraph workflow on that file.
4. Prints a summary and detailed execution log.
5. Generates a PNG diagram of the workflow graph.
"""

import sys
from pathlib import Path

# ----------------------------------------------------------------------
# Path setup
# ----------------------------------------------------------------------

# Absolute path to this file: .../LLM-CyberAttacker-Final-Project/src/tests/test_langgraph.py
THIS_FILE = Path(__file__).resolve()

# Project root: .../LLM-CyberAttacker-Final-Project
PROJECT_ROOT = THIS_FILE.parents[2]

# Ensure project root is on sys.path so "src.modules" is importable
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Now imports should work as "from src.modules ..."
from src.modules.cyber_attack_graph import run_cyber_attack, show_graph_png


def test_cyber_attack_graph() -> None:
    """
    Run the LangGraph cyber-attack workflow on a sample file and print results.
    """

    print("Testing LangGraph cyber-attack graph")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Build absolute path to the test file
    # Directory structure:
    #   PROJECT_ROOT/
    #       src/
    #           data/
    #               LCP-Data set/
    #                   Files/
    #                       File2.txt
    # ------------------------------------------------------------------
    src_dir = PROJECT_ROOT / "src"
    test_file = src_dir / "data" / "LCP-Data set" / "Files" / "File2.txt"

    print(f"Using test file: {test_file}")

    # Ensure the file exists and is a regular file before calling the graph
    if not test_file.exists() or not test_file.is_file():
        print("ERROR: Test file does not exist or is not a regular file.")
        print("Please check that this path is correct and the file is present.")
        return

    # ------------------------------------------------------------------
    # Run the LangGraph workflow
    # ------------------------------------------------------------------
    try:
        # run_cyber_attack returns a CyberState dict
        state = run_cyber_attack(str(test_file))

        print("\nWorkflow summary")
        print("-" * 40)

        error_message = state.get("error_message")
        success = not bool(error_message)

        print(f"File path in state: {state.get('file_path')}")
        print(f"Connections OK: {state.get('connections_ok', False)}")
        print(f"Success: {success}")
        print(f"Error message: {error_message or 'None'}")

        # Print sandbox result (if present) in truncated form
        sandbox_result = state.get("sandbox_result")
        if sandbox_result:
            print("\nSandbox result (truncated)")
            print("-" * 40)
            max_len = 1000
            if len(sandbox_result) > max_len:
                print(sandbox_result[:max_len] + "...")
            else:
                print(sandbox_result)

        # Print detailed execution log
        print("\nExecution log")
        print("-" * 40)
        for idx, line in enumerate(state.get("logs", []), start=1):
            print(f"{idx:02d}. {line}")

        # ------------------------------------------------------------------
        # Generate a visual diagram of the graph
        # ------------------------------------------------------------------
        out_png = THIS_FILE.parent / "cyber_attack_graph.png"
        png_bytes = show_graph_png()
        out_png.write_bytes(png_bytes)

        print(f"\nGraph diagram written to: {out_png}")

    except Exception as exc:
        # Catch any unexpected exception from the workflow or imports
        print(f"Test failed with exception: {exc}")


if __name__ == "__main__":
    test_cyber_attack_graph()
