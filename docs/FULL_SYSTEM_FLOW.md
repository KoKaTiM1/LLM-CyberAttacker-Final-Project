# LLM Cyber Attacker — Full System Flow

## Overview

The system is an **automated LLM-based Cyber Attack Agent** built on **LangGraph**.  
It receives either a **CVE ID** or a **vulnerable C file**, and attempts to generate and execute an exploit script in a sandboxed environment.

If the attack fails — or if the LLM refuses to generate code — the system enters a **retry loop** that rebuilds the prompt with feedback and tries again (up to 3 retries).

---

## System Components

| Component | File | Role |
|-----------|------|------|
| LLM Interface | `src/modules/LLM.py` | Communication with Ollama (model: `gpt-oss:20b`) |
| Agent | `src/modules/Agent.py` | Exploit script generation, code extraction from markdown |
| Orchestrator | `src/modules/orchestrator.py` | CWE → expert profile mapping, dynamic prompt assembly |
| CVE Database | `src/modules/cve_database.py` | CVE lookup from JSONL file (200K+ entries) |
| Sandbox | `src/modules/sandbox.py` | 3 execution environments: Docker, E2B API, VirtualBox |
| LangGraph Graph | `src/modules/cyber_attack_graph.py` | Node/edge definitions, routing logic |
| Wrapper | `src/modules/agent_langgraph_wrapper.py` | Business logic for each node (step functions) |

**Supported vulnerability types:**  
Buffer Overflow (CWE-119, 120, 121, 122, 125, 787) and Format String (CWE-134)

---

## Complete Flow Diagram

```
                              ┌─────────────────┐
                              │      START      │
                              └────────┬────────┘
                                       │
                                       ▼
                            ┌─────────────────────┐
                            │  check_connections   │
                            │  (Ollama API ping)   │
                            └────────┬────────────┘
                                     │
                          ┌──────────┴──────────┐
                          │                     │
                    input_type="cve"      input_type="file"
                          │                     │
                          ▼                     ▼
                  ┌───────────────┐    ┌────────────────┐
                  │   load_cve    │    │  validate_file  │
                  │ (DB lookup +  │    │ (check exists,  │
                  │  CWE support) │    │  read content)  │
                  └───────┬───────┘    └───────┬────────┘
                          │                    │
                          ▼                    ▼
                  ┌───────────────┐    ┌────────────────────┐
                  │  build_prompt  │    │ analyze_vulnerability│
                  │ (Orchestrator: │    │ (LLM identifies     │
                  │  expert profile│    │  vuln type in file,  │
                  │  + vuln logic) │    │  builds prompt)      │
                  └───────┬───────┘    └───────┬──────────────┘
                          │                    │
                          └────────┬───────────┘
                                   │
                                   ▼
                      ┌──────────────────────┐
                 ┌───▶│ create_attack_script  │◀──────────────────┐
                 │    │ (LLM generates        │                   │
                 │    │  Python exploit)       │                   │
                 │    └──────────┬─────────────┘                  │
                 │               │                                │
                 │       ┌───────┴────────┐                       │
                 │       │                │                       │
                 │  script_success   script_failed                │
                 │  (valid code)    (LLM refused /                │
                 │       │          returned None)                │
                 │       ▼                │                       │
                 │  ┌──────────────────┐  │                       │
                 │  │execute_in_sandbox│  │                       │
                 │  │(Docker, E2B,     │  │                       │
                 │  │ VirtualBox)      │  │                       │
                 │  └────────┬─────────┘  │                       │
                 │           │            │                       │
                 │    ┌──────┴──────┐     │                       │
                 │    │             │     │                       │
                 │  success      failure  │                       │
                 │    │             │     │                       │
                 │    ▼             ▼     ▼                       │
                 │  ┌────────┐  ┌──────────────────────┐          │
                 │  │workflow │  │evaluate_attack_result │          │
                 │  │complete │  │                      │          │
                 │  │ (done!) │  │ Classifies failure:  │          │
                 │  └───┬────┘  │ • LLM_REFUSAL        │          │
                 │      │       │ • SCRIPT_ERROR        │          │
                 │      ▼       │ • ATTACK_FAILED       │          │
                 │    ┌───┐     │ • INFRA_ERROR         │          │
                 │    │END│     └──────────┬─────────────┘          │
                 │    └───┘               │                       │
                 │                ┌───────┴────────┬──────────┐   │
                 │                │                │          │   │
                 │           INFRA_ERROR     retries left  retries│
                 │                │                │       exhausted
                 │                ▼                ▼          │   │
                 │          ┌────────────┐  ┌──────────────┐  │   │
                 │          │handle_error│  │rebuild_prompt │  │   │
                 │          └─────┬──────┘  │              │  │   │
                 │                │         │Adds feedback:│  │   │
                 │                ▼         │• What failed │  │   │
                 │              ┌───┐       │• Suggestions │  │   │
                 │              │END│       │• Prev script │  │   │
                 │              └───┘       │• CVE/file ctx│  │   │
                 │                          └──────┬───────┘  │   │
                 │                                 │          │   │
                 └─────────────────────────────────┘          │   │
                           (retry loop)                       │   │
                                                              ▼   │
                                                        ┌────────┐│
                                                        │workflow ││
                                                        │complete ││
                                                        │(failed) ││
                                                        └───┬────┘│
                                                            ▼     │
                                                          ┌───┐   │
                                                          │END│   │
                                                          └───┘   │
```

---

## Node Details

### 1. `check_connections`
- **Action:** Pings Ollama API at `localhost:11434`
- **Success →** Routes to `load_cve` (CVE mode) or `validate_file` (File mode)
- **Failure →** `handle_error`

### 2. `load_cve` (CVE mode only)
- **Action:** Searches CVE in JSONL database, extracts CWE, validates it's a supported type
- **Success →** `build_prompt`
- **Failure →** `handle_error` (CVE not found / unsupported CWE)

### 3. `build_prompt` (CVE mode only)
- **Action:** Orchestrator maps CWE → expert profile + vulnerability logic → assembles system_prompt + user_prompt
- **Success →** `create_attack_script`
- **Failure →** `handle_error`

### 4. `validate_file` (File mode only)
- **Action:** Checks file exists, is `.c`/`.txt`, reads content
- **Success →** `analyze_vulnerability`
- **Failure →** `handle_error`

### 5. `analyze_vulnerability` (File mode only)
- **Action:** Sends file to LLM to identify vulnerability type (Buffer Overflow / Format String), builds dynamic prompts via Orchestrator
- **Success →** `create_attack_script`
- **Failure →** `handle_error` (no supported vuln found)

### 6. `create_attack_script` ⟲
- **Action:** Sends system_prompt + user_prompt to LLM, asks for Python exploit script
- **Success (valid script) →** `execute_in_sandbox`
- **Failure (LLM refused / returned None) →** `evaluate_attack_result` **(PROPOSED CHANGE)**

### 7. `execute_in_sandbox`
- **Action:** Runs exploit in Docker, E2B, VirtualBox. Analyzes output for success/failure indicators
- **Success →** `workflow_complete`
- **Failure →** `evaluate_attack_result`

### 8. `evaluate_attack_result`
- **Action:** Analyzes what went wrong. Classifies into:

| Category | Meaning | Next Step |
|----------|---------|-----------|
| `LLM_REFUSAL` | LLM said "I can't help" | `rebuild_prompt` (strengthen academic context) |
| `SCRIPT_ERROR` | SyntaxError, ImportError, etc. | `rebuild_prompt` (fix code issues) |
| `ATTACK_FAILED` | Code ran, exploit didn't work | `rebuild_prompt` (adjust offsets/approach) |
| `INFRA_ERROR` | Docker down, timeout, etc. | `handle_error` (can't fix by retrying) |

- Also checks: `retry_count >= max_retries (3)?` → if exhausted → `workflow_complete`

### 9. `rebuild_prompt` ⟲
- **Action:** Appends feedback section to user_prompt:
  - Previous attempt feedback (what failed, suggestions)
  - CVE context reminder (CVE mode) / source code reference (File mode)
  - If LLM_REFUSAL: strengthens system_prompt with academic research framing
- **Always →** `create_attack_script` (back to retry loop)

### 10. `workflow_complete`
- **Action:** Marks workflow done. Contains success or failure summary with all attempt history.
- **→** `END`

### 11. `handle_error`
- **Action:** Logs the unrecoverable error.
- **→** `END`

---

## Retry Loop Summary

```
Attempt 1:  create_attack_script → execute_in_sandbox → FAIL
                                                          ↓
            evaluate (retry_count=1) → rebuild_prompt → create_attack_script
                                                          ↓
Attempt 2:  create_attack_script → execute_in_sandbox → FAIL
                                                          ↓
            evaluate (retry_count=2) → rebuild_prompt → create_attack_script
                                                          ↓
Attempt 3:  create_attack_script → execute_in_sandbox → FAIL
                                                          ↓
            evaluate (retry_count=3) → max_retries reached → workflow_complete (failure)
```

**Note:** If `create_attack_script` itself fails (LLM refusal), it skips the sandbox and goes directly to `evaluate_attack_result`, saving time.

---

## State Fields

### Input Fields
| Field | Type | Description |
|-------|------|-------------|
| `input_type` | `str` | `"file"`, `"cve"`, or `"invalid"` |
| `file_path` | `str` | Path to C file (File mode) |
| `file_content` | `str` | File contents (File mode) |
| `cve_id` | `str` | CVE identifier (CVE mode) |

### CVE / Prompt Fields
| Field | Type | Description |
|-------|------|-------------|
| `cve_data` | `Dict` | Full CVE record from database |
| `cwe_id` | `str` | Extracted CWE (e.g., `"CWE-119"`) |
| `system_prompt` | `str` | Expert profile prompt from Orchestrator |
| `user_prompt` | `str` | Task-specific prompt (grows with feedback on retry) |
| `prompt_metadata` | `Dict` | Category, expert profile name, etc. |

### Exploitation Fields
| Field | Type | Description |
|-------|------|-------------|
| `vulnerability_data` | `Dict` | Identified vulnerability details |
| `llm_response` | `str` | Raw LLM analysis response |
| `attack_script` | `str` | Generated Python exploit script |
| `sandbox_result` | `str` | JSON results from sandbox execution |

### Retry Fields
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `retry_count` | `int` | `0` | Current retry attempt number |
| `max_retries` | `int` | `3` | Maximum retry attempts |
| `attack_feedback` | `Dict` | `{}` | Feedback from last failed attempt |
| `attack_history` | `List[Dict]` | `[]` | All attempts: script + result + feedback |

### Status Fields
| Field | Type | Description |
|-------|------|-------------|
| `connections_ok` | `bool` | API connection status |
| `error_message` | `str` | Error message (if any) |
| `current_state` | `str` | Current `WorkflowState` value |
| `execution_log` | `List[str]` | Step-by-step execution log |

---

## Proposed Change: Script-Level Retry

### Current Behavior
When `create_attack_script` fails (LLM refuses or returns None):
```
create_attack_script → set_error() → handle_error → END  ❌ (no retry)
```

### Proposed Behavior
```
create_attack_script → SCRIPT_FAILED → evaluate_attack_result → rebuild_prompt → retry  ✅
```

**Changes required:**
1. `route_after_create_script`: route `SCRIPT_FAILED` → `evaluate_attack_result` instead of `handle_error`
2. `create_attack_script_step`: on failure, set `current_state = SCRIPT_FAILED` without calling `set_error()` (to avoid `error_message` triggering `handle_error`)
