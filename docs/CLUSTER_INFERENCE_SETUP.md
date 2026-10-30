# Cluster Inference Setup

This branch supports running LLM inference through a remote `llama.cpp` HTTP API while keeping:

- RAG retrieval local
- Docker sandbox execution local

## 1. Configure `.env`

Example:

```env
INFERENCE_BACKEND=remote
FALLBACK_INFERENCE_BACKEND=local

LOCAL_OLLAMA_URL=http://localhost:11434/api/generate
LOCAL_LLM_MODEL=huihui_ai/deepseek-r1-abliterated:14b-qwen-distill
LOCAL_RAG_LLM_MODEL=llama3.2:1b

REMOTE_LLAMACPP_URL=http://cluster-host:8080/completion
REMOTE_LLAMACPP_API_STYLE=raw
REMOTE_LLM_MODEL=your-cluster-model
REMOTE_RAG_LLM_MODEL=your-cluster-model
REMOTE_LLAMACPP_API_KEY=

OLLAMA_TIMEOUT_SECONDS=600
REMOTE_LLAMACPP_TIMEOUT_SECONDS=600
SANDBOX_COMMAND_TIMEOUT_SECONDS=900
```

Notes:

- `INFERENCE_BACKEND=remote` sends the main LLM calls and RAG LLM calls to the cluster.
- `FALLBACK_INFERENCE_BACKEND=local` falls back to local Ollama if the cluster request fails.
- Leave `FALLBACK_INFERENCE_BACKEND=` empty to disable fallback.
- Retrieval still uses local `data/cve.db` and `data/cve.index`.

## JCE cluster setup

The JCE Slurm repo runs `llama-server` in OpenAI-compatible mode, not raw `/completion` mode.

Use these values:

```env
INFERENCE_BACKEND=remote
FALLBACK_INFERENCE_BACKEND=local

REMOTE_LLAMACPP_URL=http://localhost:8080/v1/chat/completions
REMOTE_LLAMACPP_API_STYLE=openai
REMOTE_LLM_MODEL=model
REMOTE_RAG_LLM_MODEL=model
REMOTE_LLAMACPP_API_KEY=
```

Why:

- the cluster `server.sbatch` and `server-speedrun-rtx3070.sbatch` launch `llama-server`
- the exposed API is OpenAI-compatible
- the repo already supports this via `REMOTE_LLAMACPP_API_STYLE=openai`

### Typical JCE flow

1. SSH to the cluster login node:

```powershell
ssh -i C:\Users\dani0\.ssh\id_ed25519 danielcohn@192.168.200.2
```

2. Start the server from `~/jce-llama-cpp-slurm`, for example:

```bash
MODEL_PATH=./models/Qwen_Qwen3.6-35B-A3B-Q4_K_M.gguf \
  N_CPU_MOE=34 CTX=262144 CTK=turbo4 CTV=turbo3 \
  sbatch server-speedrun-rtx3070.sbatch
```

3. Find the compute node from the job log or `squeue`.

4. From your local machine, create the tunnel through the login node:

```powershell
ssh -L 8080:<compute-node>:8080 -i C:\Users\dani0\.ssh\id_ed25519 danielcohn@192.168.200.2
```

5. Keep the tunnel open and run this project locally with the JCE `.env` values above.

The project will then send both:

- main workflow LLM calls
- RAG LLM synthesis calls

to the cluster server, while keeping retrieval and Docker local.

## 2. Verify connectivity

```powershell
python -c "from src.modules.LLM import checkConnectionWithOllama; print(checkConnectionWithOllama())"
```

The message is generic now: it checks the configured inference backend, not only Ollama.

## 3. Run the workflow

```powershell
python -c "import json; from src.modules.cyber_attack_graph import run_cyber_attack; r=run_cyber_attack(file_path='demos/vulnerable_example.c'); print(json.dumps({'current_state': r.get('current_state'), 'error_message': r.get('error_message')}, indent=2))"
```

## 4. Current architecture

- File/CVE orchestration: local Python process
- Retrieval: local
- Inference: remote or local, selected by env
- Sandbox/Docker: local
