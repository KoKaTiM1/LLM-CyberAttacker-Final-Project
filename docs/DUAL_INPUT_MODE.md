# Dual Input Mode - Feature Documentation

## Overview

The system now supports **TWO input modes** with automatic detection:

### 1️⃣ File-Based Analysis
Provide a file path containing vulnerable code - the system will:
- Analyze the file to identify vulnerability type
- Support only Buffer Overflow and Format String vulnerabilities
- Automatically build appropriate expert prompts
- Generate exploitation scripts

### 2️⃣ CVE-Based Analysis  
Provide a CVE ID - the system will:
- Load CVE data from database (187,714 CVEs)
- Validate it's a supported type (Buffer Overflow or Format String)
- Build dynamic prompts based on CWE mapping
- Generate exploitation scripts

---

## Automatic Detection

The system **automatically detects** input type:

```python
from modules.cyber_attack_graph import run_cyber_attack

# CVE Input (auto-detected)
result = run_cyber_attack(user_input="CVE-2008-0888")

# File Input (auto-detected)
result = run_cyber_attack(user_input="demos/vulnerable_example.c")

# Invalid Input (rejected)
result = run_cyber_attack(user_input="some random text")
```

### Detection Rules

| Input Pattern | Type | Example |
|--------------|------|---------|
| `CVE-YYYY-NNNNN` | CVE | CVE-2008-0888 |
| Path with `/` or `\\` | File | src/vulnerable.c |
| Filename with extension | File | vulnerable.c |
| Existing file path | File | C:\\code\\vuln.c |
| Anything else | Invalid | ❌ Rejected |

---

## Workflow Differences

### 📁 FILE MODE Flow
```
Input: "vulnerable.c"
↓
Step 1: check_connections
↓
Step 4: validate_file (קובץ קיים?)
↓
Step 5: analyze_vulnerability (LLM מזהה סוג פגיעות)
↓
Step 6: create_attack_script
↓
Step 7: execute_in_sandbox
```

### 🔍 CVE MODE Flow
```
Input: "CVE-2008-0888"
↓
Step 1: check_connections
↓
Step 2: load_cve (טעינה מDB + בדיקת תמיכה)
↓
Step 3: build_prompt (בניית prompts דינמיים)
↓
Step 5: analyze_vulnerability
↓
Step 6: create_attack_script
↓
Step 7: execute_in_sandbox
```

**Key Difference:** File mode skips Steps 2-3, goes directly to file validation and analysis.

---

## Demo Scripts

### 1. File Input Demo
```bash
python demos/demo_file_input.py
```
Demonstrates file-based vulnerability analysis using `demos/vulnerable_example.c`

### 2. CVE Input Demo
```bash
python demos/demo_cve_input.py
```
Demonstrates CVE-based analysis using CVE-2008-0888

### 3. Dual Input Demo
```bash
python demos/demo_dual_input.py
```
Comprehensive demo showing both modes, auto-detection, and invalid input rejection

---

## Code Changes

### Modified Files

1. **`agent_langgraph_wrapper.py`**
   - Added `detect_input_type()` function - automatic input type detection
   - Updated `AgentContext.__init__()` - supports `user_input` parameter
   - Enhanced `analyze_vulnerability_step()` - dual mode support (file vs CVE)

2. **`cyber_attack_graph.py`**
   - Added `input_type` field to `CyberState`
   - Updated routing logic - `route_after_check_connections()` routes based on input type
   - Modified `run_cyber_attack()` - accepts `user_input` parameter with auto-detection

3. **`CyberState` TypedDict**
   - Added `input_type: str` field

4. **State conversion functions**
   - `_context_from_state()` - copies `input_type`
   - `_state_from_context()` - exports `input_type`

### New Files

1. **`demos/vulnerable_example.c`** - Example vulnerable C code with buffer overflow
2. **`demos/demo_file_input.py`** - File mode demonstration
3. **`demos/demo_cve_input.py`** - CVE mode demonstration  
4. **`demos/demo_dual_input.py`** - Combined dual mode demo
5. **`tests/test_input_detection.py`** - Unit tests for `detect_input_type()` (10/10 passed ✅)

---

## Supported Vulnerability Types

### ✅ Supported (Both Modes)
- **Buffer Overflow** - CWE-119, 120, 121, 122, 125, 787
- **Format String** - CWE-134

### ❌ Not Supported (Rejected)
- SQL Injection, XSS, Command Injection, Use-After-Free, Integer Overflow
- **Reason:** Incompatible with file+script sandbox execution model

---

## Usage Examples

### Method 1: Generic Input (Recommended)
```python
# Auto-detect CVE
result = run_cyber_attack(user_input="CVE-2008-0888")

# Auto-detect File
result = run_cyber_attack(user_input="demos/vulnerable_example.c")
```

### Method 2: Explicit Parameters (Legacy)
```python
# Explicit CVE
result = run_cyber_attack(cve_id="CVE-2008-0888")

# Explicit File
result = run_cyber_attack(file_path="demos/vulnerable_example.c")
```

Both methods work - the generic `user_input` provides better UX.

---

## Testing

### Run Detection Tests
```bash
python tests/test_input_detection.py
```
**Result:** 10/10 tests passed ✅

### Run LangGraph Flow Tests  
```bash
python -m pytest tests/test_langgraph_flow.py -v
```
Tests CVE workflow integration with validation

### Run All Tests
```bash
python -m pytest tests/ -v
```

---

## Project Organization

Root directory has been reorganized:

```
LLM-CyberAttacker-Final-Project/
├── demos/              # Demo scripts
│   ├── demo_file_input.py
│   ├── demo_cve_input.py
│   ├── demo_dual_input.py
│   ├── demo_cve_rejection.py
│   ├── demo_full_workflow.py
│   └── vulnerable_example.c
├── docs/               # Documentation
│   ├── README_NEW_FEATURES.md
│   ├── WORKFLOW_STRUCTURE.md
│   ├── דוח_אלפא.md
│   └── template_alpha.pdf
├── tests/              # Test files
│   ├── test_input_detection.py
│   ├── test_langgraph_flow.py
│   └── test_supported_attacks.py
├── src/                # Source code
├── Scripts/            # Utility scripts
├── data/               # CVE database
└── logs/               # Execution logs
```

---

## Summary

✅ **Dual input mode implemented successfully**
✅ **Automatic type detection (CVE vs File vs Invalid)**
✅ **Two distinct workflow paths based on input**
✅ **Backward compatible (existing code still works)**
✅ **Comprehensive demos and tests**
✅ **Project structure reorganized**

The system is now more flexible and user-friendly, supporting both security researchers analyzing specific CVEs and developers testing their own code files.
