"""
rag.py

Purpose:
- Local RAG pipeline for NVD CVE JSONL data (CPU-first).
- Builds 3 documents per CVE (core / weakness / version).
- Embeds document text into vectors (cosine similarity) and indexes them in FAISS.
- Stores document text + metadata in SQLite.
- Supports retrieval and "Option 2" context packaging:
  - core docs for all selected CVEs
  - add weakness/version docs only for top M CVEs if relevant

Important:
- This module ONLY implements RAG (document creation, indexing, retrieval).
- It does not generate exploit/attack content.

Dependencies:
- faiss-cpu
- numpy
- sentence-transformers (for local embeddings)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import faiss
import numpy as np

# Local modules
from config import RagConfig
from resources import Resources

# IMPORTANT:
# Avoid naming a local file "types.py" because it can collide with Python stdlib "types".
# This import supports both names:
# - preferred: rag_types.py
# - legacy:    types.py (not recommended)
try:
    from rag_types import RAGDocument, RetrievedDocument, make_rag_document
except ImportError:  # pragma: no cover
    from types import RAGDocument, RetrievedDocument, make_rag_document  # type: ignore


# ---------------------------
# Embedding
# ---------------------------

class LocalEmbedder:
    """
    Local embedding wrapper using Sentence-Transformers.

    Notes:
    - Downloads model weights on first run (unless already cached).
    - Subsequent runs can be offline using the cached model.
    - Returns normalized float32 vectors for cosine similarity.
    """

    def __init__(self, model_name: str):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as e:
            raise RuntimeError(
                "Missing dependency 'sentence-transformers'. Install with:\n"
                "  pip install -U sentence-transformers"
            ) from e

        self.model_name = model_name
        self.model = SentenceTransformer(model_name)

        # Probe dimension once to avoid hardcoding.
        probe = self.model.encode(["dimension_probe"], normalize_embeddings=True, convert_to_numpy=True)
        self.dim = int(probe.shape[1])

    def embed_texts(self, texts: Sequence[str]) -> np.ndarray:
        """
        Convert a batch of texts into normalized embeddings.
        Shape: (len(texts), dim) float32
        """
        vecs = self.model.encode(
            list(texts),
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        return vecs.astype(np.float32)

    def embed_query(self, query: str) -> np.ndarray:
        """
        Embed a single query into a normalized embedding.
        Shape: (1, dim)
        """
        return self.embed_texts([query])


# ---------------------------
# SQLite Storage
# ---------------------------

class SqliteDocStore:
    """
    SQLite store for:
    - Document text
    - Metadata JSON
    - Common metadata columns for filtering
    - Mapping to FAISS integer IDs
    """

    def __init__(self, sqlite_path: str):
        self.sqlite_path = sqlite_path
        self.conn = sqlite3.connect(sqlite_path)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS docs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                faiss_id INTEGER UNIQUE NOT NULL,
                cve_id TEXT NOT NULL,
                doc_type TEXT NOT NULL,
                text TEXT NOT NULL,

                bucket TEXT,
                bucket_source TEXT,

                validated_only INTEGER NOT NULL,
                vuln_status TEXT,

                cwe_primary TEXT,

                cvss_version TEXT,
                cvss_score REAL,
                cvss_vector TEXT,

                is_linux_kernel INTEGER NOT NULL,
                version_summary TEXT,

                subsystem_prefix TEXT,
                has_file_path INTEGER NOT NULL,

                published TEXT,
                last_modified TEXT,

                metadata_json TEXT NOT NULL
            );
            """
        )

        # Indexes for filtering and grouping
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_docs_cve_id ON docs(cve_id);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_docs_doc_type ON docs(doc_type);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_docs_bucket ON docs(bucket);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_docs_linux ON docs(is_linux_kernel);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_docs_cwe ON docs(cwe_primary);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_docs_cvss_score ON docs(cvss_score);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_docs_subsystem ON docs(subsystem_prefix);")
        self.conn.commit()

    def insert_document(self, faiss_id: int, doc: RAGDocument) -> None:
        md = doc.metadata

        # Normalize booleans to integers for SQLite
        validated_only = 1 if bool(md.get("validated_only", False)) else 0
        is_linux_kernel = 1 if bool(md.get("is_linux_kernel", False)) else 0
        has_file_path = 1 if bool(md.get("has_file_path", False)) else 0

        self.conn.execute(
            """
            INSERT INTO docs(
                faiss_id, cve_id, doc_type, text,
                bucket, bucket_source,
                validated_only, vuln_status, cwe_primary,
                cvss_version, cvss_score, cvss_vector,
                is_linux_kernel, version_summary,
                subsystem_prefix, has_file_path,
                published, last_modified,
                metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                faiss_id,
                doc.cve_id,
                doc.doc_type,
                doc.text,
                md.get("bucket"),
                md.get("bucket_source"),
                validated_only,
                md.get("vuln_status"),
                md.get("cwe_primary"),
                md.get("cvss_version"),
                md.get("cvss_score"),
                md.get("cvss_vector"),
                is_linux_kernel,
                md.get("version_summary"),
                md.get("subsystem_prefix"),
                has_file_path,
                md.get("published"),
                md.get("last_modified"),
                json.dumps(md, ensure_ascii=False),
            ),
        )

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def fetch_by_faiss_ids(self, faiss_ids: List[int]) -> Dict[int, RAGDocument]:
        """
        Retrieve stored documents by FAISS IDs.
        """
        if not faiss_ids:
            return {}

        placeholders = ",".join("?" for _ in faiss_ids)
        cur = self.conn.execute(
            f"SELECT faiss_id, cve_id, doc_type, text, metadata_json FROM docs WHERE faiss_id IN ({placeholders});",
            tuple(faiss_ids),
        )

        out: Dict[int, RAGDocument] = {}
        for faiss_id, cve_id, doc_type, text, md_json in cur.fetchall():
            md = json.loads(md_json)
            out[int(faiss_id)] = RAGDocument(cve_id=cve_id, doc_type=doc_type, text=text, metadata=md)
        return out

    def fetch_by_cve_id(self, cve_id: str) -> List[RAGDocument]:
        """
        Direct lookup by CVE ID: returns all doc types stored for that CVE.
        """
        cur = self.conn.execute(
            "SELECT cve_id, doc_type, text, metadata_json FROM docs WHERE cve_id = ?;",
            (cve_id,),
        )
        docs: List[RAGDocument] = []
        for cve_id, doc_type, text, md_json in cur.fetchall():
            md = json.loads(md_json)
            docs.append(RAGDocument(cve_id=cve_id, doc_type=doc_type, text=text, metadata=md))
        return docs


# ---------------------------
# Document builders (core / weakness / version)
# ---------------------------

def _pick_primary_metric(metrics_list: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Choose the metric entry where type == 'Primary' if present; else first.
    """
    if not metrics_list:
        return None
    for m in metrics_list:
        if m.get("type") == "Primary":
            return m
    return metrics_list[0]


def _extract_en_description(cve: Dict[str, Any], langs: Set[str]) -> Tuple[str, bool]:
    """
    Extract first description matching requested languages, prefer English if included.
    """
    descs = cve.get("descriptions", [])
    if not isinstance(descs, list):
        return "", False

    if "en" in langs:
        for d in descs:
            if d.get("lang") == "en" and isinstance(d.get("value"), str):
                return d["value"], True

    for d in descs:
        if d.get("lang") in langs and isinstance(d.get("value"), str):
            return d["value"], True

    return "", False


def _extract_cwes(cve: Dict[str, Any]) -> Set[str]:
    """
    Extract CWE IDs from cve.weaknesses[].description[].value == "CWE-XXX"
    """
    out: Set[str] = set()
    weaknesses = cve.get("weaknesses", [])
    if not isinstance(weaknesses, list):
        return out

    for w in weaknesses:
        descs = w.get("description", [])
        if not isinstance(descs, list):
            continue
        for d in descs:
            val = d.get("value")
            if isinstance(val, str) and val.startswith("CWE-"):
                out.add(val)
    return out


def _extract_linux_kernel_bounds(cve: Dict[str, Any]) -> Tuple[bool, Dict[str, Optional[str]]]:
    """
    Extract Linux kernel version bounds from configurations.
    Returns:
      (is_linux_kernel, bounds_dict)
    """
    configs = cve.get("configurations", [])
    if not isinstance(configs, list):
        return False, {}

    matches: List[Dict[str, Any]] = []

    for conf in configs:
        nodes = conf.get("nodes", [])
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            if not isinstance(cpe_matches, list):
                continue
            for m in cpe_matches:
                criteria = m.get("criteria")
                if isinstance(criteria, str) and "cpe:2.3:o:linux:linux_kernel" in criteria:
                    matches.append(m)

    if not matches:
        return False, {}

    def score_match(mm: Dict[str, Any]) -> Tuple[int, int]:
        end_inc = mm.get("versionEndIncluding")
        end_exc = mm.get("versionEndExcluding")
        end_score = 2 if isinstance(end_inc, str) else (1 if isinstance(end_exc, str) else 0)
        end_val = end_inc if isinstance(end_inc, str) else (end_exc if isinstance(end_exc, str) else "")
        spec = len(end_val)
        return (end_score, spec)

    best = sorted(matches, key=score_match, reverse=True)[0]

    bounds = {
        "versionStartIncluding": best.get("versionStartIncluding"),
        "versionStartExcluding": best.get("versionStartExcluding"),
        "versionEndIncluding": best.get("versionEndIncluding"),
        "versionEndExcluding": best.get("versionEndExcluding"),
    }

    for k, v in list(bounds.items()):
        if not isinstance(v, str):
            bounds[k] = None

    return True, bounds


def _format_version_summary(bounds: Dict[str, Optional[str]]) -> str:
    """
    Build a deterministic human-readable version summary.
    """
    vsi = bounds.get("versionStartIncluding")
    vse = bounds.get("versionStartExcluding")
    vei = bounds.get("versionEndIncluding")
    vee = bounds.get("versionEndExcluding")

    parts: List[str] = []
    if vsi:
        parts.append(f">= {vsi}")
    elif vse:
        parts.append(f"> {vse}")

    if vei:
        parts.append(f"<= {vei}")
    elif vee:
        parts.append(f"< {vee}")

    return " ".join(parts) if parts else "unknown"


def build_core_document(record: Dict[str, Any], resources: Resources, cfg: RagConfig) -> RAGDocument:
    """
    Build the 'core' document for a CVE record.
    - CWE classification first; keyword fallback if CWE yields unknown.
    - CVSS v3 Primary else first; fallback to v2 Primary else first; else unknown.
    - Extract linux kernel bounds from CPE configurations.
    - Extract file path/subsystem from description via Resources patterns.
    """
    if "cve" not in record or not isinstance(record["cve"], dict):
        raise ValueError("Invalid record: missing top-level 'cve' object.")

    cve = record["cve"]

    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not cve_id.strip():
        raise ValueError("Invalid record: missing/empty cve.id")

    vuln_status = cve.get("vulnStatus", "unknown")
    published = cve.get("published", "unknown")
    last_modified = cve.get("lastModified", "unknown")

    description_en, has_en_desc = _extract_en_description(cve, cfg.description_langs)

    # CWE extraction + bucket classification with keyword fallback
    cwe_set = _extract_cwes(cve)
    cwe_list = sorted(cwe_set)
    cwe_primary = cwe_list[0] if cwe_list else "none"

    bucket_initial = resources.classify_bucket_from_cwes(cwe_set)
    bucket_source = "cwe"

    bucket = bucket_initial
    if bucket == resources.BUCKET_UNKNOWN:
        bucket_kw = resources.classify_bucket_from_keywords(description_en)
        bucket = bucket_kw
        bucket_source = "keyword" if bucket != resources.BUCKET_UNKNOWN else "unknown"

    # CVSS extraction (v3 preferred, else v2, else unknown)
    metrics = cve.get("metrics", {}) if isinstance(cve.get("metrics", {}), dict) else {}

    cvss_version = "unknown"
    cvss_score = None
    cvss_vector = None

    v3_list = metrics.get("cvssMetricV30", [])
    if isinstance(v3_list, list) and v3_list:
        chosen = _pick_primary_metric(v3_list)
        if chosen and isinstance(chosen.get("cvssData"), dict):
            data = chosen["cvssData"]
            cvss_version = "3.x"
            cvss_score = data.get("baseScore")
            cvss_vector = data.get("vectorString")

    if cvss_version == "unknown":
        v2_list = metrics.get("cvssMetricV2", [])
        if isinstance(v2_list, list) and v2_list:
            chosen = _pick_primary_metric(v2_list)
            if chosen and isinstance(chosen.get("cvssData"), dict):
                data = chosen["cvssData"]
                cvss_version = "2.0"
                cvss_score = data.get("baseScore")
                cvss_vector = data.get("vectorString")

    if not isinstance(cvss_score, (int, float)):
        cvss_score = None
    if not isinstance(cvss_vector, str):
        cvss_vector = None

    # Linux kernel bounds
    is_linux_kernel, bounds = _extract_linux_kernel_bounds(cve)
    version_summary = _format_version_summary(bounds) if is_linux_kernel else "unknown"

    # File path + subsystem prefix
    file_path = resources.extract_file_path(description_en) if has_en_desc else None
    subsystem_prefix = resources.derive_subsystem_prefix(file_path) if file_path else None
    has_file_path = bool(file_path)

    core_metadata: Dict[str, Any] = {
        "cve_id": cve_id,
        "doc_type": "core",
        "vuln_status": vuln_status,
        "published": published,
        "last_modified": last_modified,
        "has_en_desc": has_en_desc,
        "cwe_primary": cwe_primary,
        "cwe_list": cwe_list,
        "bucket_initial": bucket_initial,
        "bucket": bucket,
        "bucket_source": bucket_source,
        "cvss_version": cvss_version,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "is_linux_kernel": is_linux_kernel,
        "version_summary": version_summary,
        **bounds,
        "file_path": file_path,
        "subsystem_prefix": subsystem_prefix,
        "has_file_path": has_file_path,
        "validated_only": bool(cfg.validated_only),
        "linux_only": bool(cfg.linux_only),
    }

    cwe_str = ", ".join(cwe_list) if cwe_list else "none"
    cvss_str = (
        f"CVSS: {cvss_version} {cvss_score} | Vector: {cvss_vector}"
        if cvss_version != "unknown" and cvss_score is not None and cvss_vector
        else "CVSS: unknown"
    )
    file_str = file_path if file_path else "none"
    affected_str = f"linux_kernel {version_summary}" if is_linux_kernel else "unknown"

    core_text = "\n".join(
        [
            f"CVE: {cve_id}",
            f"Status: {vuln_status}",
            f"Bucket: {bucket}",
            f"CWE: {cwe_str}",
            f"Description: {description_en or 'unknown'}",
            f"Affected: {affected_str}",
            cvss_str,
            f"File: {file_str}",
            f"Published: {published}",
            f"LastModified: {last_modified}",
        ]
    )

    return make_rag_document(
        cve_id=cve_id,
        doc_type="core",
        text=core_text,
        metadata=core_metadata,
        allowed_doc_types=resources.DOC_TYPES,
    )


def build_weakness_document(core_doc: RAGDocument, resources: Resources) -> RAGDocument:
    """
    Build the 'weakness' document for a CVE using core metadata.
    Focus: CWE/bucket/pattern summary.
    """
    md = core_doc.metadata
    cve_id = core_doc.cve_id

    bucket = md.get("bucket", resources.BUCKET_UNKNOWN)
    cwe_list = md.get("cwe_list", [])
    cwe_str = ", ".join(cwe_list) if cwe_list else "none"

    cwe_set = set(cwe_list) if isinstance(cwe_list, list) else set()
    if "CWE-134" in cwe_set:
        pattern = "externally controlled format string"
    elif "CWE-125" in cwe_set:
        pattern = "out-of-bounds read"
    elif "CWE-787" in cwe_set:
        pattern = "out-of-bounds write"
    else:
        pattern = (
            "buffer overflow / bounds error"
            if bucket in (resources.BUCKET_OVERFLOW_FAMILY, resources.BUCKET_BOTH)
            else "unknown"
        )

    cvss_vector = md.get("cvss_vector") if isinstance(md.get("cvss_vector"), str) else None
    cvss_version = md.get("cvss_version", "unknown")

    weakness_metadata = dict(md)
    weakness_metadata.update({"doc_type": "weakness", "pattern": pattern})

    weakness_text_lines = [
        f"CVE: {cve_id}",
        f"Bucket: {bucket}",
        f"CWE: {cwe_str}",
        f"Pattern: {pattern}",
    ]
    if cvss_vector and cvss_version != "unknown":
        weakness_text_lines.append(f"CVSSVector: {cvss_vector}")

    weakness_text = "\n".join(weakness_text_lines)

    return make_rag_document(
        cve_id=cve_id,
        doc_type="weakness",
        text=weakness_text,
        metadata=weakness_metadata,
        allowed_doc_types=resources.DOC_TYPES,
    )


def build_version_document(core_doc: RAGDocument, resources: Resources) -> RAGDocument:
    """
    Build the 'version' document for a CVE using core metadata.
    Focus: version bounds, CPE scope, dates.
    """
    md = core_doc.metadata
    cve_id = core_doc.cve_id

    is_linux_kernel = bool(md.get("is_linux_kernel", False))
    version_summary = md.get("version_summary", "unknown")
    published = md.get("published", "unknown")
    last_modified = md.get("last_modified", "unknown")

    vsi = md.get("versionStartIncluding")
    vse = md.get("versionStartExcluding")
    vei = md.get("versionEndIncluding")
    vee = md.get("versionEndExcluding")

    version_metadata = dict(md)
    version_metadata.update({"doc_type": "version"})

    lines = [
        f"CVE: {cve_id}",
        "Product: linux_kernel" if is_linux_kernel else "Product: unknown",
        f"VersionSummary: {version_summary}",
        f"VersionStartIncluding: {vsi or 'none'}",
        f"VersionStartExcluding: {vse or 'none'}",
        f"VersionEndIncluding: {vei or 'none'}",
        f"VersionEndExcluding: {vee or 'none'}",
        f"Published: {published}",
        f"LastModified: {last_modified}",
    ]
    version_text = "\n".join(lines)

    return make_rag_document(
        cve_id=cve_id,
        doc_type="version",
        text=version_text,
        metadata=version_metadata,
        allowed_doc_types=resources.DOC_TYPES,
    )


# ---------------------------
# Index building (FAISS + SQLite)
# ---------------------------

def build_index(cfg: RagConfig, resources: Resources, embedder: LocalEmbedder) -> None:
    """
    Build FAISS + SQLite index from JSONL input.
    """
    if not os.path.exists(cfg.input_jsonl_path):
        raise FileNotFoundError(f"Input JSONL not found: {cfg.input_jsonl_path}")

    index = faiss.IndexFlatIP(embedder.dim)
    store = SqliteDocStore(cfg.sqlite_path)

    total_lines = 0
    indexed_docs = 0
    faiss_id = 0

    batch_docs: List[RAGDocument] = []
    batch_texts: List[str] = []

    def flush_batch() -> None:
        nonlocal faiss_id, indexed_docs
        if not batch_docs:
            return

        vecs = embedder.embed_texts(batch_texts)  # normalized float32
        index.add(vecs)

        for doc in batch_docs:
            store.insert_document(faiss_id=faiss_id, doc=doc)
            faiss_id += 1
            indexed_docs += 1

        store.commit()
        batch_docs.clear()
        batch_texts.clear()

    with open(cfg.input_jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            total_lines += 1
            raw = line.strip()
            if not raw:
                continue

            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                continue

            try:
                core = build_core_document(record, resources, cfg)
            except Exception as e:
                print(f"[SKIP] core doc build failed at line {total_lines}: {e}", file=sys.stderr)
                continue

            if cfg.linux_only and not bool(core.metadata.get("is_linux_kernel", False)):
                continue

            if cfg.validated_only:
                status = str(core.metadata.get("vuln_status", ""))
                if status.lower() in {"rejected", "deferred", "awaiting analysis", "undergoing analysis"}:
                    continue

            try:
                weakness = build_weakness_document(core, resources)
                version = build_version_document(core, resources)
            except Exception as e:
                print(f"[SKIP] aux doc build failed for {core.cve_id}: {e}", file=sys.stderr)
                continue

            for doc in (core, weakness, version):
                batch_docs.append(doc)
                batch_texts.append(doc.text)

            if len(batch_docs) >= 512:
                flush_batch()

            if cfg.progress_every > 0 and total_lines % cfg.progress_every == 0:
                print(f"Processed {total_lines:,} lines | indexed docs so far: {indexed_docs:,}")

    flush_batch()

    os.makedirs(os.path.dirname(cfg.faiss_index_path) or ".", exist_ok=True)
    faiss.write_index(index, cfg.faiss_index_path)

    store.close()

    print("Index build complete.")
    print(f"- Lines processed: {total_lines:,}")
    print(f"- Documents indexed: {indexed_docs:,} (expected ~3 per CVE kept)")
    print(f"- SQLite: {cfg.sqlite_path}")
    print(f"- FAISS:  {cfg.faiss_index_path}")


# ---------------------------
# Retrieval + Option 2 context packaging
# ---------------------------

@dataclass(frozen=True)
class CVEAggregate:
    cve_id: str
    score: float
    core: Optional[RetrievedDocument]
    weakness: Optional[RetrievedDocument]
    version: Optional[RetrievedDocument]


def _query_has_version_intent(query: str) -> bool:
    q = query.lower()
    if any(tok in q for tok in ["<=", ">=", " through ", " before ", " after ", " up to ", " version "]):
        return True
    return bool(re.search(r"\b\d+\.\d+(?:\.\d+)?\b", query))


def retrieve_documents(
    query: str,
    cfg: RagConfig,
    resources: Resources,
    embedder: LocalEmbedder,
    store: SqliteDocStore,
    index: faiss.Index,
    top_k_docs: int = 300,
) -> List[RetrievedDocument]:
    """
    Retrieve top_k_docs documents from FAISS and return as RetrievedDocument list
    (including text+metadata from SQLite).
    """
    q_vec = embedder.embed_query(query)
    scores, ids = index.search(q_vec, top_k_docs)
    scored_ids = [(int(i), float(s)) for i, s in zip(ids[0], scores[0]) if i != -1]

    doc_map = store.fetch_by_faiss_ids([i for i, _ in scored_ids])

    results: List[RetrievedDocument] = []
    for faiss_id, score in scored_ids:
        doc = doc_map.get(faiss_id)
        if doc is None:
            continue

        if cfg.linux_only and not bool(doc.metadata.get("is_linux_kernel", False)):
            continue
        if cfg.validated_only:
            status = str(doc.metadata.get("vuln_status", ""))
            if status.lower() in {"rejected", "deferred", "awaiting analysis", "undergoing analysis"}:
                continue

        results.append(RetrievedDocument(document=doc, score=score, faiss_id=faiss_id))

    return results


def aggregate_by_cve(retrieved: List[RetrievedDocument]) -> List[CVEAggregate]:
    """
    Group retrieved documents by CVE ID and compute a CVE-level score.
    """
    by_cve: Dict[str, Dict[str, RetrievedDocument]] = {}

    for hit in retrieved:
        cve_id = hit.document.cve_id
        doc_type = hit.document.doc_type
        by_cve.setdefault(cve_id, {})
        cur = by_cve[cve_id].get(doc_type)
        if cur is None or hit.score > cur.score:
            by_cve[cve_id][doc_type] = hit

    aggregates: List[CVEAggregate] = []
    for cve_id, docs in by_cve.items():
        core = docs.get("core")
        weakness = docs.get("weakness")
        version = docs.get("version")

        score = 0.0
        if core:
            score = max(score, 1.00 * core.score)
        if weakness:
            score = max(score, 0.85 * weakness.score)
        if version:
            score = max(score, 0.70 * version.score)

        aggregates.append(CVEAggregate(cve_id=cve_id, score=score, core=core, weakness=weakness, version=version))

    aggregates.sort(key=lambda a: a.score, reverse=True)
    return aggregates


def build_llm_context_option2(
    query: str,
    ranked: List[CVEAggregate],
    n_cves: int = 15,
    top_m_deep: int = 5,
) -> List[str]:
    """
    Option 2 context packaging:
    - Include core for all selected CVEs.
    - Include weakness for top M CVEs (always).
    - Include version for top M CVEs only if query has version intent.
    """
    version_intent = _query_has_version_intent(query)
    selected = ranked[:n_cves]

    blocks: List[str] = []
    for idx, agg in enumerate(selected):
        if agg.core:
            blocks.append(agg.core.document.text)

        if idx < top_m_deep:
            if agg.weakness:
                blocks.append(agg.weakness.document.text)
            if version_intent and agg.version:
                blocks.append(agg.version.document.text)

    return blocks


# ---------------------------
# Public API for integration (single call from llm.py)
# ---------------------------

_CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


def _order_docs_for_exact_lookup(docs: List[RAGDocument]) -> List[RAGDocument]:
    order = {"core": 0, "weakness": 1, "version": 2}
    return sorted(docs, key=lambda d: order.get(d.doc_type, 99))


def call_rag(
    *,
    user_context: str,
    sqlite_path: str,
    faiss_path: str,
    model_name: str,
    linux_only: bool = True,
    validated_only: bool = True,
    top_k_docs: int = 300,
    n_cves: int = 15,
    top_m_deep: int = 5,
) -> Dict[str, Any]:
    """
    Single entry point for your pipeline:

    - If user_context contains a CVE ID: exact lookup from SQLite (core/weakness/version).
    - Else: semantic retrieval (FAISS + embeddings) and Option-2 context packaging.

    Returns:
    - mode: "exact" | "semantic"
    - selected_cves: list[str]
    - context_blocks: list[str]
    - optional reason if not found
    """
    resources = Resources()
    store = SqliteDocStore(sqlite_path)

    # 1) Exact lookup if user provided CVE-ID
    m = _CVE_ID_PATTERN.search(user_context or "")
    if m:
        cve_id = m.group(0).upper()
        docs = store.fetch_by_cve_id(cve_id)
        store.close()

        if not docs:
            return {
                "mode": "exact",
                "selected_cves": [],
                "context_blocks": [],
                "reason": f"CVE not found: {cve_id}",
            }

        ordered = _order_docs_for_exact_lookup(docs)
        return {
            "mode": "exact",
            "selected_cves": [cve_id],
            "context_blocks": [d.text for d in ordered],
        }

    # 2) Semantic retrieval otherwise
    index = faiss.read_index(faiss_path)
    embedder = LocalEmbedder(model_name)

    cfg = RagConfig(
        input_jsonl_path="",
        output_jsonl_path=None,
        sqlite_path=sqlite_path,
        faiss_index_path=faiss_path,
        linux_only=linux_only,
        validated_only=validated_only,
        progress_every=0,
    )

    retrieved = retrieve_documents(
        query=user_context,
        cfg=cfg,
        resources=resources,
        embedder=embedder,
        store=store,
        index=index,
        top_k_docs=top_k_docs,
    )
    ranked = aggregate_by_cve(retrieved)
    context_blocks = build_llm_context_option2(
        query=user_context,
        ranked=ranked,
        n_cves=n_cves,
        top_m_deep=top_m_deep,
    )

    store.close()

    if not ranked:
        return {
            "mode": "semantic",
            "selected_cves": [],
            "context_blocks": [],
            "reason": "No results for the given context (after filters).",
        }

    selected_cves = [agg.cve_id for agg in ranked[:n_cves]]
    return {
        "mode": "semantic",
        "selected_cves": selected_cves,
        "context_blocks": context_blocks,
    }


# ---------------------------
# CLI
# ---------------------------

def _load_faiss_index(path: str) -> faiss.Index:
    if not os.path.exists(path):
        raise FileNotFoundError(f"FAISS index not found: {path}")
    return faiss.read_index(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Local CVE RAG (FAISS + SQLite)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Build index
    p_build = sub.add_parser("build", help="Build FAISS+SQLite index from JSONL")
    p_build.add_argument("--input", required=True, help="Input JSONL path")
    p_build.add_argument("--sqlite", required=True, help="SQLite DB path")
    p_build.add_argument("--faiss", required=True, help="FAISS index path")
    p_build.add_argument("--model", required=True, help="Sentence-Transformers model name")
    p_build.add_argument("--linux-only", action="store_true", help="Keep Linux kernel CVEs only")
    p_build.add_argument("--validated-only", action="store_true", help="Keep validated-only (enforced)")
    p_build.add_argument("--progress-every", type=int, default=10_000, help="Progress print frequency (lines)")

    # Query
    p_query = sub.add_parser("query", help="Query the local index and print Option-2 context blocks")
    p_query.add_argument("--sqlite", required=True, help="SQLite DB path")
    p_query.add_argument("--faiss", required=True, help="FAISS index path")
    p_query.add_argument("--model", required=True, help="Sentence-Transformers model name")
    p_query.add_argument("--q", required=True, help="Query text")
    p_query.add_argument("--linux-only", action="store_true", help="Filter to Linux kernel only")
    p_query.add_argument("--validated-only", action="store_true", help="Filter to validated-only")
    p_query.add_argument("--top-k-docs", type=int, default=300, help="FAISS top-K documents")
    p_query.add_argument("--n-cves", type=int, default=15, help="Number of CVEs to select")
    p_query.add_argument("--top-m-deep", type=int, default=5, help="Depth CVEs (add weakness/version)")

    args = parser.parse_args()
    resources = Resources()

    if args.cmd == "build":
        cfg = RagConfig(
            input_jsonl_path=args.input,
            output_jsonl_path=None,
            sqlite_path=args.sqlite,
            faiss_index_path=args.faiss,
            linux_only=bool(args.linux_only),
            validated_only=bool(args.validated_only),
            progress_every=int(args.progress_every),
        )
        embedder = LocalEmbedder(args.model)
        build_index(cfg, resources, embedder)

    elif args.cmd == "query":
        cfg = RagConfig(
            input_jsonl_path="",
            output_jsonl_path=None,
            sqlite_path=args.sqlite,
            faiss_index_path=args.faiss,
            linux_only=bool(args.linux_only),
            validated_only=bool(args.validated_only),
            progress_every=0,
        )
        embedder = LocalEmbedder(args.model)
        store = SqliteDocStore(cfg.sqlite_path)
        index = _load_faiss_index(cfg.faiss_index_path)

        retrieved = retrieve_documents(
            query=args.q,
            cfg=cfg,
            resources=resources,
            embedder=embedder,
            store=store,
            index=index,
            top_k_docs=int(args.top_k_docs),
        )

        ranked = aggregate_by_cve(retrieved)
        context_blocks = build_llm_context_option2(
            query=args.q,
            ranked=ranked,
            n_cves=int(args.n_cves),
            top_m_deep=int(args.top_m_deep),
        )

        print(f"Retrieved CVEs: {min(len(ranked), int(args.n_cves))}")
        print("-" * 80)
        for i, block in enumerate(context_blocks, start=1):
            print(f"[CONTEXT {i}]")
            print(block)
            print("-" * 80)

        store.close()


if __name__ == "__main__":
    main()