# CVE RAG Pipeline

Local Retrieval-Augmented Generation pipeline over NVD CVE data.  
No external API calls — embedding and search run fully on CPU.

---

## Files

| File | Purpose |
|---|---|
| `rag.py` | Core pipeline: document builders, FAISS index, retrieval, `call_rag()` |
| `rag_types.py` | Shared dataclasses: `RAGDocument`, `RetrievedDocument`, `make_rag_document()` |
| `config.py` | `RagConfig` — all runtime settings in one place |
| `resources.py` | Constants: CWE families, keyword lists, regex patterns, bucket classifier |

---

## Step 1 — Build the index (run once)

```python
from rag import build_index, LocalEmbedder
from config import RagConfig
from resources import Resources

cfg = RagConfig(
    input_jsonl_path="data/nvd_cves_filtered_buffer_overflow_format_string.jsonl",
    output_jsonl_path=None,
    sqlite_path="data/cve_rag.sqlite",
    faiss_index_path="data/cve_rag.faiss",
    linux_only=False,
    validated_only=False,
)

embedder = LocalEmbedder("BAAI/bge-m3")
build_index(cfg, Resources(), embedder)
```

Or via CLI:

```bash
python src/modules/rag/rag.py build \
  --input  data/nvd_cves_filtered_buffer_overflow_format_string.jsonl \
  --sqlite data/cve_rag.sqlite \
  --faiss  data/cve_rag.faiss \
  --model  BAAI/bge-m3
```

---

## Step 2 — Query at runtime

```python
from rag import call_rag

result = call_rag(
    user_context="heap-based buffer overflow in linux kernel usb driver",
    sqlite_path="data/cve_rag.sqlite",
    faiss_path="data/cve_rag.faiss",
    model_name="BAAI/bge-m3",

    # Optional (defaults shown):
    linux_only=True,    # keep only Linux kernel CVEs
    validated_only=True, # skip rejected / unreviewed CVEs
    top_k_docs=300,     # FAISS retrieval pool size
    n_cves=15,          # CVEs included in final context
    top_m_deep=5,       # top N also get weakness + version blocks
)

if not result["context_blocks"]:
    print("No results:", result.get("reason"))
else:
    context_for_llm = "\n\n".join(result["context_blocks"])
    selected_cves   = result["selected_cves"]   # e.g. ["CVE-2024-1234", ...]
    mode            = result["mode"]             # "exact" | "semantic"
```

### Exact CVE lookup

If `user_context` contains a CVE ID (`CVE-YYYY-NNNNN`), the pipeline skips
embedding entirely and fetches the stored documents directly from SQLite:

```python
result = call_rag(
    user_context="tell me about CVE-2024-1234",
    sqlite_path="data/cve_rag.sqlite",
    faiss_path="data/cve_rag.faiss",
    model_name="BAAI/bge-m3",
)
# result["mode"] == "exact"
# result["context_blocks"] has up to 3 entries: core, weakness, version
```

---

## What a context block looks like

Each CVE produces **3 blocks** — all sharing the same CVE ID:

```
--- core ---
CVE: CVE-2017-18009
Status: Analyzed
Bucket: overflow_family
CWE: CWE-125
Description: heap-based buffer over-read in cv::HdrDecoder::checkSignature ...
Affected: unknown
CVSS: 3.x 7.5 | Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
File: modules/imgcodecs/src/grfmt_hdr.cpp
Published: 2018-01-01T08:29:00.283

--- weakness ---
CVE: CVE-2017-18009
Bucket: overflow_family
CWE: CWE-125
Pattern: out-of-bounds read
CVSSVector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

--- version ---
CVE: CVE-2017-18009
Product: unknown
VersionSummary: unknown
VersionStartIncluding: none
...
```

For semantic queries `call_rag` returns:
- **core** block for every selected CVE (`n_cves`)
- **weakness** block for the top `top_m_deep` CVEs
- **version** block for the top `top_m_deep` CVEs only if the query mentions a version number or range keyword (`before`, `through`, `up to`, etc.)

---

## Dependencies

```
faiss-cpu
numpy
sentence-transformers
```
