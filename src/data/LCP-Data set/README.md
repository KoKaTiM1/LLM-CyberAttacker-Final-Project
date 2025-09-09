# LCP-Data Set — Low‑Level C Vulnerabilities

## Overview
A compact, hands‑on dataset of **C source snippets** paired one‑to‑one with **LLM result JSONs**.  
Use it to benchmark vulnerability detection (static or LLM‑based), train/evaluate classifiers, or prototype pipelines focused on memory safety, concurrency, and OS interaction.

- **Scope:** 22 C files and 22 JSON files (1:1 mapping)
- **Language:** C only
- **Goal:** Provide small, realistic code examples with clear labels and model outputs

## Directory Structure
```
LCP-Data set/
├── Files/                 # C snippets (File1.txt ... File22.txt)
└── LLM Results/           # JSON results (File1.json ... File22.json)
```
**Mapping rule:** `Files/FileN.txt` ↔ `LLM Results/FileN.json` (matching stem `FileN`)  
Note: the root folder contains a space. Quote it in shells: `cd "LCP-Data set"`

## How to Read the Dataset
Each C file in `Files/` has a **matching JSON** in `LLM Results/` with the same base name.  
The JSON explains the vulnerability class (ground truth) and what the LLM predicted.

**Typical JSON fields**
- `file_name`: logical file stem (e.g., `"File7"`)
- `vulnerability_name`: ground‑truth vulnerability class for the C snippet
- `vulnerability_found_by_llm`: model‑predicted class
- `vulnerability_description_by_llm`: brief rationale from the model
- `llm_model`: model identifier


