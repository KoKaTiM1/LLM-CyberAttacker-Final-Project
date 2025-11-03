# 🛡️ LLM CyberAttacker Final Project

AI-powered system that learns to generate and execute cyber attacks against vulnerable code.

## 📋 Project Components

- **Agent.py** - Main LLM agent orchestrating attacks
- **Factory.py** - Creates and manages attack strategies  
- **LLM.py** - Language model integration and learning
- **sandbox.py** - Secure execution environment (testing component)

## 🔄 Complete Workflow

1. **Agent** reads vulnerable C files → Analyzes vulnerabilities
2. **Factory** generates attack scripts → Creates exploits based on file type  
3. **Sandbox** executes attacks → Tests script + target file safely
4. **LLM** processes results → Learns from success/failure feedback
5. **Agent** adjusts & retries → Improves attacks based on learning

---

## 🧪 Sandbox Testing Component

The sandbox is a **testing component** that safely executes attack scripts across 3 isolated environments.

### 🚀 Test Sandbox Component

```bash
# Test sandbox functionality (recommended first)
python src/modules/sandbox.py --config sandbox_config.json --test basic_test

# Test vulnerability detection
python src/modules/sandbox.py --config sandbox_config.json --test vulnerability_test

# Interactive mode for custom scripts
python src/modules/sandbox.py --config sandbox_config.json --interactive
```

### 📞 Using Sandbox in Main Project

```python
from src.modules.sandbox import SandboxManager

# Initialize sandbox
sandbox = SandboxManager("sandbox_config.json")
sandbox.connect_all()

# Execute attack with target file
results = sandbox.execute_exploit(
    exploit_script="your_attack_script.py",
    vulnerability_data={
        "Type": "buffer overflow", 
        "Location": "line 42",
        "Target_File": "vulnerable.c"
    }
)

# Get detailed results
print(f"Success: {results['exploitation_successful']}")
print(f"Environments tested: {results['environments_tested']}")
print(f"Learning suggestions: {results['summary']['learning_suggestions']}")
```

### 📤 Sandbox Output Format

```json
{
  "status": "success",
  "exploitation_successful": true,
  "environments_tested": 3,
  "results": {
    "Docker_Container": {
      "success": true,
      "output": "exploit output...",
      "exploitation_analysis": {
        "exploitation_successful": true,
        "success_indicators": ["shell spawned", "code execution"],
        "suggestions": ["Try different payload", "Bypass ASLR"]
      }
    }
  },
  "summary": {
    "successful_exploitations": 2,
    "learning_suggestions": ["Recalculate buffer offsets", "Try ROP chains"]
  }
}
```

### 📋 Sandbox Requirements

**Software:** Python 3.11+, Docker Desktop, VirtualBox, E2B API key  
**Setup:** `pip install e2b-code-interpreter`  
**Config:** Create `sandbox_config.json` in project root directory

### ⚙️ sandbox_config.json Format

Create this file in the **root directory** of your project:

```json
{
  "environments": {
    "docker": {
      "enabled": true,
      "image": "python:3.11-slim",
      "container_name": "sandbox-test",
      "docker_command": "docker"
    },
    "e2b": {
      "enabled": true,
      "api_key": "your_e2b_api_key_here"
    },
    "virtualbox": {
      "enabled": true,
      "vm_name": "your_vm_name_here",
      "username": "your_vm_username",
      "password": "your_vm_password",
      "vboxmanage_path": "VBoxManage",
      "python_path": "/usr/bin/python3",
      "startup_wait_time": 60
    }
  },
  "test_scripts": {
    "basic_test": "import sys\nprint(f'Python version: {sys.version}')",
    "vulnerability_test": "print('Testing vulnerability detection...')"
  }
}
```

**Required Changes:**
- Replace `your_e2b_api_key_here` with your E2B API key
- Replace `your_vm_name_here` with your VirtualBox VM name
- Update VM username/password to match your setup

### 🔧 Sandbox Troubleshooting

- **VM issues:** Check VirtualBox VM name and Guest Additions
- **E2B errors:** Verify API key and internet connection  
- **Docker problems:** Ensure Docker Desktop is running

---
*Sandbox component ready for integration with Agent, Factory, and LLM modules* 🎯