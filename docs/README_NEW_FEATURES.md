# 🆕 New Features - CVE-Based Dynamic Workflow

## 📋 What's New (February 2026)

The system has been upgraded with a complete **CVE-based dynamic workflow** that automatically:
1. 🔍 Loads CVE data from a local database
2. 🧠 Maps vulnerabilities to expert profiles
3. 📝 Builds dynamic, context-aware prompts
4. ⚡ Generates targeted exploits
5. 🔬 Tests in sandbox environments

---

## 🏗️ New Architecture

```
User Input (CVE ID)
      ↓
[CVE Database] → Load vulnerability data
      ↓
[Orchestrator] → Map CWE → Expert Profile + Vulnerability Logic
      ↓
[Dynamic Prompts] → System: Expert Role | User: CVE Context + Logic
      ↓
[LLM Analysis] → Generate exploit with specialized knowledge
      ↓
[Sandbox Testing] → Execute and validate
```

---

## 🆕 New Modules

### 1. **CVE Database** (`src/modules/cve_database.py`)

Manages access to CVE data from `data/nvd_cves_all.jsonl`.

**Features:**
- 🔍 Search by CVE ID
- 🏷️ Filter by CWE (weakness type)
- 🏢 Filter by vendor/manufacturer
- ⚠️ Filter by severity (CVSS score)
- 📊 Advanced multi-criteria filtering

**Example:**
```python
from src.modules.cve_database import CVEDatabase

db = CVEDatabase()

# Get specific CVE
cve = db.get_by_id("CVE-2024-1234")

# Filter by CWE
buffer_overflows = db.filter_by_cwe("CWE-119", limit=10)

# Filter by vendor
microsoft_cves = db.filter_by_vendor("Microsoft", limit=10)

# Filter by severity
critical_cves = db.filter_by_severity(min_score=9.0, max_score=10.0, limit=10)

# Advanced filtering
results = db.advanced_filter(
    cwe_id="CWE-119",
    vendor="Apache",
    min_severity=7.0,
    limit=5
)
```

---

### 2. **Enhanced Orchestrator** (already existed, now integrated)

The `PromptOrchestrator` now powers the entire workflow:

**Mapping Process:**
```
CVE Data → Extract CWE → Lookup in cwe_mapping.json
    ↓
CWE-119 → {
    expert_profile: "binary_exploitation.txt",
    vulnerability_logic: "buffer_overflow.txt",
    category: "memory_corruption"
}
    ↓
Load Files → Assemble Dynamic Prompts
```

**Configuration:** `src/config/cwe_mapping.json`

Supports 15+ CWE types:
- CWE-119, CWE-120, CWE-121, CWE-122 → Buffer Overflow
- CWE-89 → SQL Injection
- CWE-79 → XSS
- CWE-77, CWE-78 → Command Injection
- And more...

---

## 🔄 Updated Workflow

### Old Workflow:
```python
# Hard-coded prompts, file-based only
context = AgentContext(file_path="vulnerable.c")
wrapper = CyberAttackAgentWrapper()
result = wrapper.run(context)
```

### New Workflow:
```python
# Dynamic prompts, CVE-based
context = AgentContext(cve_id="CVE-2024-1234")
wrapper = CyberAttackAgentWrapper()
result = wrapper.run(context)

# Workflow automatically:
# 1. Loads CVE from database
# 2. Identifies CWE-119 (buffer overflow)
# 3. Loads binary_exploitation expert profile
# 4. Loads buffer_overflow methodology
# 5. Builds specialized prompts
# 6. Generates exploit
# 7. Tests in sandbox
```

---

## 🚀 Quick Start

### Option 1: Test with Demo Script

```bash
# Interactive demo with CVE search
python demo_cve_workflow.py
```

### Option 2: Full Test Suite

```bash
# Comprehensive testing
python test_new_workflow.py
```

### Option 3: Use in Your Code

```python
from src.modules.agent_langgraph_wrapper import CyberAttackAgentWrapper, AgentContext

# Initialize
wrapper = CyberAttackAgentWrapper()

# Create context with CVE ID
context = AgentContext(cve_id="CVE-2024-1234")

# Run workflow
result = wrapper.run(context)

# Check results
if result.error_message:
    print(f"Error: {result.error_message}")
else:
    print(f"Success! Generated exploit:")
    print(result.attack_script)
    print(f"\nUsed expert: {result.prompt_metadata['expert_profile']}")
    print(f"Category: {result.prompt_metadata['category']}")
```

---

## 📊 Workflow Steps (Detailed)

### Step 1: Check Connections
- ✓ Verify Ollama LLM is running
- ✓ Check API connectivity

### Step 2: Load CVE Data (**NEW**)
- 📥 Read from `data/nvd_cves_all.jsonl`
- 🔍 Search by CVE ID
- 📋 Extract metadata, description, CVSS, references

### Step 3: Build Dynamic Prompts (**NEW**)
- 🧬 Extract CWE from CVE data
- 🗺️ Map CWE → Expert Profile + Logic
- 📂 Load `expert_profiles/*.txt`
- 📂 Load `vulnerability_logic/*.txt`
- 🔧 Assemble system + user prompts

### Step 4: Validate File (Optional)
- 📄 If file path provided, validate C file
- ⏭️ Skip if CVE-only mode

### Step 5: Analyze Vulnerability
- 🧠 Send dynamic prompts to LLM
- 📥 Receive vulnerability analysis
- ✅ Parse and validate response

### Step 6: Generate Exploit
- 💻 Use vulnerability data + prompts
- 🎯 Generate targeted exploit code
- 🔍 Extract Python code from response

### Step 7: Execute in Sandbox
- 🐳 Run in Docker container
- 💻 Run in VirtualBox VM
- ☁️ Run in E2B cloud sandbox
- 📊 Analyze results from all environments

---

## 🗂️ File Structure

```
LLM-CyberAttacker-Final-Project/
│
├── src/
│   ├── modules/
│   │   ├── cve_database.py          ← NEW: CVE data management
│   │   ├── orchestrator.py          ← ENHANCED: Now integrated
│   │   ├── agent_langgraph_wrapper.py ← UPDATED: Added CVE steps
│   │   ├── cyber_attack_graph.py    ← UPDATED: New state fields
│   │   ├── Agent.py                 ← UPDATED: Dynamic prompts
│   │   ├── LLM.py                   ← UPDATED: New LLM function
│   │   ├── sandbox.py               ← Unchanged
│   │   └── Factory.py               ← Unchanged
│   │
│   ├── config/
│   │   ├── cwe_mapping.json         ← CWE → Profile mapping
│   │   └── sandbox_config.json
│   │
│   ├── expert_profiles/             ← Expert role prompts
│   │   ├── binary_exploitation.txt
│   │   ├── web_security.txt
│   │   ├── memory_corruption.txt
│   │   └── default_expert.txt
│   │
│   └── vulnerability_logic/         ← Exploitation methodologies
│       ├── buffer_overflow.txt
│       ├── sql_injection.txt
│       ├── command_injection.txt
│       └── ...
│
├── data/
│   └── nvd_cves_all.jsonl          ← CVE database (required)
│
├── demo_cve_workflow.py            ← NEW: Quick demo
├── test_new_workflow.py            ← NEW: Full test suite
├── demo_orchestrator.py            ← OLD: Orchestrator demo
└── README_NEW_FEATURES.md          ← This file
```

---

## 🎯 Use Cases

### Use Case 1: Research Specific CVE
```python
# Target a known vulnerability
context = AgentContext(cve_id="CVE-2021-44228")  # Log4Shell
result = wrapper.run(context)
```

### Use Case 2: Test All Buffer Overflows
```python
db = CVEDatabase()
buffer_overflow_cves = db.filter_by_cwe("CWE-119", limit=20)

for cve in buffer_overflow_cves:
    cve_id = cve['id']
    context = AgentContext(cve_id=cve_id)
    result = wrapper.run(context)
    # Analyze results...
```

### Use Case 3: Focus on Critical Vendor CVEs
```python
db = CVEDatabase()
critical_apache = db.advanced_filter(
    vendor="Apache",
    min_severity=9.0,
    limit=10
)

for cve in critical_apache:
    # Generate exploits for critical Apache vulnerabilities
    ...
```

---

## ⚙️ Configuration

### CVE Database
- **Location:** `data/nvd_cves_all.jsonl`
- **Format:** JSONL (JSON Lines) - one CVE per line
- **Source:** NVD (National Vulnerability Database)

### CWE Mapping
- **Location:** `src/config/cwe_mapping.json`
- **Purpose:** Maps CWE IDs to expert profiles and logic files
- **Customizable:** Add your own CWE mappings

### Expert Profiles
- **Location:** `src/expert_profiles/`
- **Purpose:** System prompts defining the AI's expertise
- **Customizable:** Create new profiles for specific domains

### Vulnerability Logic
- **Location:** `src/vulnerability_logic/`
- **Purpose:** Detailed exploitation methodologies
- **Customizable:** Add new vulnerability types

---

## 🧪 Testing

### Test CVE Database Only
```python
from src.modules.cve_database import CVEDatabase

db = CVEDatabase()

# Get stats
stats = db.get_statistics()
print(f"Total CVEs: {stats['total_cves']}")

# Test search
cve = db.get_by_id("CVE-2024-1234")
if cve:
    print(f"Found: {cve['id']}")
```

### Test Orchestrator Only
```python
from src.modules.orchestrator import PromptOrchestrator
from src.modules.cve_database import CVEDatabase

db = CVEDatabase()
cve_data = db.get_by_id("CVE-2024-1234")

orchestrator = PromptOrchestrator()
prompt = orchestrator.assemble_prompt(cve_data)

print(f"Expert: {prompt.metadata['expert_profile']}")
print(f"System Prompt: {prompt.system_prompt[:200]}...")
```

### Test Full Workflow
```bash
python test_new_workflow.py
```

---

## 📈 Benefits of New Architecture

| Feature | Old Approach | New Approach |
|---------|-------------|--------------|
| **Prompt** | Hard-coded | Dynamic, expert-specific |
| **Input** | File only | CVE ID (+ optional file) |
| **Context** | Generic | CWE-aware, category-specific |
| **Scalability** | Manual per-type | Automatic via mapping |
| **Searchability** | None | Filter by CWE, vendor, severity |
| **Expertise** | Single role | Multiple expert profiles |

---

## 🔮 Future Enhancements

### Planned Features:
1. **RAG Database** - Vector search for similar vulnerabilities
2. **Dynamic Containers** - Auto-build vulnerable environments
3. **MCP Integration** - Model Context Protocol support
4. **Multi-LLM** - Support for different models per expert
5. **Learning Loop** - Improve prompts based on success rate

---

## 📝 Notes

- ⚠️ Requires `data/nvd_cves_all.jsonl` file
- 🐋 Ollama must be running for LLM operations
- 🔬 Sandbox testing requires additional setup (Docker, VirtualBox, or E2B)
- 🎓 Designed for academic/research purposes only

---

## 🤝 Contributing

To add support for new CWE types:

1. Add mapping to `src/config/cwe_mapping.json`
2. Create expert profile in `src/expert_profiles/`
3. Create vulnerability logic in `src/vulnerability_logic/`
4. Test with relevant CVEs

---

## 📚 Resources

- **NVD CVE Database:** https://nvd.nist.gov/
- **CWE List:** https://cwe.mitre.org/
- **Ollama:** https://ollama.ai/

---

**Last Updated:** February 2026  
**Version:** 2.0 - CVE Integration Complete
