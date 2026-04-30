# CVE RAG Integration (Project Flow)

This module is used inside the project pipeline:

1. User query enters the project flow
2. RAG returns focused CVE context/answer
3. The project logic continues in the existing agent flow (analysis/generation steps)

The goal here is simple: call RAG from Python code (not from terminal manually each time).

## Main API to Use

Use `call_agentic_rag` from `src.modules.rag.agent_rag`.

```python
from src.modules.rag.agent_rag import call_agentic_rag

result = call_agentic_rag(
    user_query="Find format string vulnerabilities relevant to Linux kernel",
    sqlite_path="data/cve.db",
    faiss_path="data/cve.index",
    model_name="all-MiniLM-L6-v2",   # embedding model
    llm_model_name="gpt-oss:20b",     # Ollama model
    top_k_docs=80,
    n_cves=8,
    top_m_deep=3,
)

answer = result["final_answer"]
steps = result["conversation_length"]
messages = result["messages"]
```

## How to Use in Project Code

### In `LLM.py`

Add a small wrapper and call it from your main flow when you need CVE context.

```python
from src.modules.rag.agent_rag import call_agentic_rag

def get_rag_answer(user_query: str) -> str:
    result = call_agentic_rag(
        user_query=user_query,
        sqlite_path="data/cve.db",
        faiss_path="data/cve.index",
        model_name="all-MiniLM-L6-v2",
        llm_model_name="gpt-oss:20b",
        top_k_docs=80,
        n_cves=8,
        top_m_deep=3,
    )
    return result["final_answer"]
```

### In `Agent.py`

Use the returned answer/context in your next stage logic.

```python
rag_answer = get_rag_answer(user_query)
# continue with existing agent processing...
```

## Expected Return Object

`call_agentic_rag(...)` returns:

- `final_answer`: final text answer from the RAG agent
- `messages`: internal message history
- `conversation_length`: number of graph steps/messages

## One-Time Setup

Build index once (or when dataset changes):

```bash
python src/modules/rag/rag.py build \
  --input data/nvd_cves_filtered_buffer_overflow_format_string.jsonl \
  --sqlite data/cve.db \
  --faiss data/cve.index \
  --model all-MiniLM-L6-v2
```

## Quick Terminal Check (Optional)

```bash
python -c "from src.modules.rag.agent_rag import call_agentic_rag; r=call_agentic_rag(user_query='Find format string vulnerabilities relevant to Linux kernel', sqlite_path='data/cve.db', faiss_path='data/cve.index', model_name='all-MiniLM-L6-v2', llm_model_name='gpt-oss:20b', top_k_docs=80, n_cves=8, top_m_deep=3); print(r['final_answer'])"
```

## Notes

- `embeddings.position_ids | UNEXPECTED` during embedding model load is expected and can be ignored.
- If you get `WinError 10061`, Ollama server is not running on `127.0.0.1:11434`.
