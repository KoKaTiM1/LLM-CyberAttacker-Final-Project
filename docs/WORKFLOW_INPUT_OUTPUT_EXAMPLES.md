# Workflow Input and Output Examples

## Purpose

This document shows how the system looks in practice for the two supported entry modes:

1. `file` mode
2. `cve` mode

The goal is not to dump every state field, but to show:

- what the user gives as input
- what each major stage does
- what the important intermediate outputs look like
- what a successful final result looks like

The examples below are representative of the current workflow and are written in the same shape as the real system output.

---

## 1. File Mode Example

### Input

The user gives a real source file path.

```json
{
  "input_type": "file",
  "file_path": "demos/vulnerable_example.c"
}
```

### High-level flow

1. Detect that the input is a file
2. Check required services:
   - Ollama
   - Docker
3. Load the file from disk
4. Run RAG enrichment on the file context
5. Analyze the file with the LLM
6. Convert the file into a runnable target
7. Generate an attack script
8. Execute the attack in Docker
9. Evaluate the result

---

### Step A: File Loaded

The file is read from disk before analysis.

**Example internal state**

```json
{
  "input_type": "file",
  "file_path": "demos/vulnerable_example.c",
  "file_content": "#include <stdio.h>\n#include <string.h>\n\nint main(int argc, char *argv[]) {\n    char buffer[64];\n    strcpy(buffer, argv[1]);\n    printf(\"You entered: %s\\n\", buffer);\n    return 0;\n}\n"
}
```

**Meaning**

- `file_path` is the real source input
- `file_content` is what the analysis stages use

---

### Step B: RAG Enrichment

RAG is used to gather extra context before exploit generation.

For file mode, this usually means:

- similar vulnerability patterns
- typical exploitation behavior
- compile/runtime hints

**Example RAG output**

```json
{
  "rag_context": "The source resembles a classic stack-based buffer overflow pattern. Unsafe copying into a fixed-size stack buffer without strict bounds checking can allow overwrite of adjacent memory. For simple reproduction in a non-hardened Linux binary, useful indicators include direct argv-based input, disabled stack protector, executable stack, and non-PIE compilation. Expected successful reproduction signals include process crash, SIGSEGV, or controllable return-path corruption."
}
```

**Meaning**

- `rag_context` is not the exploit itself
- it is supporting context that helps the next LLM step produce a better attack

---

### Step C: Vulnerability Analysis LLM Output

The LLM reads the file and produces structured vulnerability understanding.

**Example LLM-style response**

```json
{
  "vulnerability_data": {
    "Type": "buffer overflow",
    "Location": "main() argv[1] -> strcpy(buffer, argv[1])",
    "Explanation": "The program copies attacker-controlled input into a fixed-size stack buffer without verifying length. If argv[1] exceeds the 64-byte local buffer, adjacent stack memory may be overwritten and the process may crash or allow control-flow corruption."
  }
}
```

**Meaning**

- `Type` is the normalized vulnerability category
- `Location` tells where the issue is in the code
- `Explanation` is the core security reasoning the exploit stage will use

---

### Step D: Target Preparation

The workflow turns the input file into a runnable Docker target.

**Example target spec**

```json
{
  "target_spec": {
    "mode": "file",
    "target_type": "local_file",
    "source_path": "demos/vulnerable_example.c",
    "container_target_path": "/tmp/target.c",
    "compile_command": "gcc /tmp/target.c -o /tmp/target -fno-stack-protector -z execstack -no-pie",
    "run_command": "/tmp/target",
    "build_strategy": "compile_source"
  }
}
```

**Meaning**

- this is the actual executable target the sandbox will run
- for C files, the system compiles a local binary inside Docker

---

### Step E: Attack Script Generation

The system generates a Python exploit/attack script aimed at the prepared target.

**Example shortened attack script**

```json
{
  "attack_script": "import subprocess\npayload = 'A' * 200\nresult = subprocess.run(['/tmp/target', payload], capture_output=True, text=True)\nprint(result.stdout)\nif result.returncode < 0:\n    print('crashed with exit status', result.returncode)\n    print('exploit successful')\n"
}
```

**Meaning**

- this is the actual script executed in Docker
- file mode usually attacks the compiled local binary directly

---

### Step F: Sandbox Execution Output

The attack script is run in Docker against the compiled file target.

**Example sandbox result**

```json
{
  "sandbox_result": {
    "Docker_Container": {
      "success": true,
      "execution_time": 12.4,
      "output": "crashed with exit status -11\nexploit successful\n",
      "error": null,
      "exploitation_analysis": {
        "exploitation_successful": true,
        "success_indicators": [
          "exploit successful",
          "crashed with exit status"
        ]
      }
    }
  }
}
```

**Meaning**

- `success: true` means the script itself ran
- `exploitation_successful: true` means the framework accepted the result as a real reproduction signal

---

### Step G: Final File Mode State

**Example final state**

```json
{
  "current_state": "sandbox_success"
}
```

**Meaning**

- the file mode workflow completed successfully
- the vulnerable target was executed and the attack was reproduced in Docker

---

## 2. CVE Mode Example

### Input

The user gives a CVE ID.

```json
{
  "input_type": "cve",
  "cve_id": "CVE-2018-7588"
}
```

### High-level flow

1. Detect that the input is a CVE
2. Check required services:
   - Ollama
   - Docker
3. Load the CVE record from the local database
4. Validate that it is in a supported vulnerability family
5. Build prompts from the CWE mapping
6. Run RAG enrichment
7. Resolve the target product/version/build path
8. Create a reproduction plan
9. Convert that plan into a runnable Docker target
10. Generate or select the attack script
11. Build and run the target in Docker
12. Evaluate the result

---

### Step A: CVE Loaded from Database

**Example internal state**

```json
{
  "input_type": "cve",
  "cve_id": "CVE-2018-7588",
  "cve_data": {
    "id": "CVE-2018-7588",
    "description": "An issue was discovered in CImg v.220. A heap-based buffer over-read in load_bmp in CImg.h occurs when loading a crafted bmp image.",
    "weaknesses": [
      {
        "value": "CWE-125"
      }
    ]
  }
}
```

**Meaning**

- the CVE is no longer just a string
- it becomes structured vulnerability intelligence loaded from the local dataset

---

### Step B: Prompt Builder / Orchestrator Output

The orchestrator uses the CWE to select the right expert context and vulnerability logic.

**Example prompt-related output**

```json
{
  "cwe_id": "CWE-125",
  "system_prompt": "You are a binary exploitation expert focused on out-of-bounds read and memory corruption vulnerabilities.",
  "user_prompt": "Analyze CVE-2018-7588 and prepare a reproducible attack plan against the affected target. Focus on the affected version, vulnerable function, realistic trigger input, and sandbox-safe reproduction signals.",
  "prompt_metadata": {
    "category": "memory_corruption",
    "expert_profile": "binary_exploitation.txt"
  }
}
```

**Meaning**

- this stage specializes the LLM behavior for the specific CVE family
- it does not build the target yet

---

### Step C: RAG Enrichment

In CVE mode, RAG is used differently than file mode.

It tries to recover:

- affected version hints
- source/build references
- PoC references
- vulnerable component context

**Example RAG output**

```json
{
  "rag_context": "Related references indicate the issue affects CImg v.220 in the BMP loading path. Public references point to a GitHub issue discussion and external PoC repository entries containing crafted payload files. The vulnerable area is associated with load_bmp behavior in CImg.h. Reproduction is more credible if the target is built from the exact upstream affected version instead of a newer distro package."
}
```

**Meaning**

- this is the key bridge between the CVE record and the Docker build plan
- it helps the framework decide whether the CVE can be turned into a real target

---

### Step D: CVE Target Resolution

This is one of the most important steps in CVE mode.

The workflow extracts concrete target information such as:

- product
- vendor
- version
- references
- possible source artifacts

**Example target-resolution output**

```json
{
  "cve_target_info": {
    "cve_id": "CVE-2018-7588",
    "cwe_id": "CWE-125",
    "description": "Heap-based buffer over-read in load_bmp in CImg.h",
    "product_hint": "cimg",
    "vendor_hint": "cimg",
    "version_hint": ".220",
    "references": [
      "https://github.com/dtschump/CImg/issues/183",
      "https://github.com/xiaoqx/pocs/tree/master/cimg"
    ],
    "source_references": [
      "https://github.com/dtschump/CImg/issues/183",
      "https://github.com/xiaoqx/pocs/tree/master/cimg"
    ],
    "missing_fields": []
  }
}
```

**Meaning**

- if `missing_fields` is empty, the framework has enough evidence to continue
- if key fields are missing, the workflow should stop as unresolved instead of pretending to reproduce the CVE

---

### Step E: Reproduction Plan

The target-resolution step is converted into an execution plan.

**Example reproduction plan**

```json
{
  "reproduction_plan": {
    "strategy": "system_package_tool",
    "tool_name": "cimg_bmp_loader",
    "executable_path": "/tmp/cimg_bmp_loader",
    "setup_commands": [
      "apt-get update -qq",
      "apt-get install -y --no-install-recommends g++ git ca-certificates",
      "git clone --depth 1 --branch v.220 --quiet https://github.com/GreycLab/CImg.git /opt/CImg",
      "git clone --depth 1 --quiet https://github.com/xiaoqx/pocs.git /opt/pocs",
      "compile local loader against /opt/CImg/CImg.h"
    ]
  }
}
```

**Meaning**

- this is the plan for constructing the vulnerable target in Docker
- this is the stage that makes CVE mode more than just “text in, exploit out”

---

### Step F: Runnable TargetSpec

The plan is normalized into a final runtime definition.

**Example target spec**

```json
{
  "target_spec": {
    "mode": "cve",
    "target_type": "cve_system_binary",
    "cve_id": "CVE-2018-7588",
    "container_target_path": "/tmp/cimg_bmp_loader",
    "run_command": "/tmp/cimg_bmp_loader",
    "build_strategy": "run_system_binary_exploit"
  }
}
```

**Meaning**

- this is what the sandbox sees as the execution target
- from this point, the workflow has enough information to try a real reproduction

---

### Step G: CVE Attack Script

For some CVEs, the system may use a curated or specialized script shape rather than a generic one.

**Example shortened attack script**

```json
{
  "attack_script": "import os\nimport subprocess\nTARGET_BIN = '/tmp/cimg_bmp_loader'\nPOC_ROOT = '/opt/pocs/cimg'\nPREFERRED_PAYLOADS = ['cimg-heap-overflow-load_bmp-48427', 'cimg-heap-overflow-load_bmp-48457']\n...\nprint('crashed with exit status', result.returncode)\nprint('exploit successful')\n"
}
```

**Meaning**

- the script is targeting a specific resolved binary and specific PoC files
- this is a stronger reproduction path than a generic abstract exploit

---

### Step H: CVE Sandbox Execution Output

**Example sandbox result**

```json
{
  "sandbox_result": {
    "Docker_Container": {
      "success": true,
      "execution_time": 34.8,
      "output": "trying payload: /opt/pocs/cimg/cimg-heap-overflow-load_bmp-48427\ncrashed with exit status -11\nexploit successful\n",
      "error": null,
      "exploitation_analysis": {
        "exploitation_successful": true,
        "success_indicators": [
          "exploit successful",
          "crashed with exit status"
        ]
      }
    }
  }
}
```

**Meaning**

- Docker built and ran the exact target version
- the PoC payload triggered a real crash signal
- the framework accepted it as successful reproduction

---

### Step I: Final CVE Mode State

**Example final state**

```json
{
  "current_state": "sandbox_success"
}
```

**Meaning**

- the CVE-driven path successfully reached a runnable target
- the target executed in Docker
- the attack was reproduced

---

## 3. Example Failure Cases

The framework should not force every CVE into Docker.

### A. Target Unresolved

```json
{
  "current_state": "target_unresolved",
  "cve_target_info": {
    "product_hint": "android",
    "version_hint": null,
    "missing_fields": [
      "affected_product_or_version",
      "source_or_build_reference"
    ]
  }
}
```

**Meaning**

- relevant CVE found
- not enough evidence to build a concrete target
- workflow stops instead of guessing

### B. Sandbox Failed

```json
{
  "current_state": "sandbox_failed"
}
```

**Meaning**

- the target was built and run
- the attack did not succeed
- the failure happened at execution/reproduction, not at CVE loading

### C. Connection Failed

```json
{
  "current_state": "connection_failed",
  "error_message": "Failed to connect to Ollama or Docker"
}
```

**Meaning**

- infrastructure was unavailable
- this is not a CVE or exploit logic problem

---

## 4. Practical Difference Between the Two Modes

### File Mode

- starts from code you already have
- target is easier to construct
- useful as the baseline demonstration

### CVE Mode

- starts from vulnerability intelligence, not local source code
- must resolve product/version/build information first
- more complex
- more important as the core project contribution

---

## 5. Final Interpretation

The framework should be understood this way:

- **File mode** answers:  
  `Can the system analyze and attack a vulnerable file I already have?`

- **CVE mode** answers:  
  `Can the system transform public vulnerability intelligence into a reproducible Docker target and then test it?`

That second question is the stronger research contribution, because it requires:

- CVE parsing
- CWE mapping
- RAG enrichment
- target reconstruction
- version-aware Docker preparation
- sandboxed execution

This is also why a CVE should only continue when the workflow can extract enough real target evidence. If it cannot resolve a concrete product/version/build path, the correct result is `target_unresolved`, not a fake reproduction claim.
