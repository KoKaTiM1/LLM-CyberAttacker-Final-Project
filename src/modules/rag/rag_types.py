"""
types.py

Purpose:
- Shared datatypes for the local CVE RAG pipeline.
- Provides a strict document factory to enforce doc_type correctness.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple


@dataclass(frozen=True)
class RAGDocument:
    """
    A single retrievable unit in your RAG system.

    Notes:
    - Multiple documents can share the same CVE ID (distinguished by doc_type).
    - doc_key is deterministic: f"{cve_id}:{doc_type}"
    """
    cve_id: str
    doc_type: str  # must be validated externally via make_rag_document()
    text: str
    metadata: Dict[str, Any]

    @property
    def doc_key(self) -> str:
        return f"{self.cve_id}:{self.doc_type}"


@dataclass(frozen=True)
class RetrievedDocument:
    """
    A retrieved RAG document with similarity score and optional FAISS id.
    """
    document: RAGDocument
    score: float
    faiss_id: Optional[int] = None


def make_rag_document(
    *,
    cve_id: str,
    doc_type: str,
    text: str,
    metadata: Dict[str, Any],
    allowed_doc_types: Iterable[str],
) -> RAGDocument:
    """
    Strict factory for RAGDocument.

    Validation rules:
    - doc_type must be in allowed_doc_types
    - cve_id must be non-empty
    - text must be non-empty (you can relax this later, but empty text breaks embeddings)

    Error handling:
    - Raises ValueError with a clear message (caller can catch and log/skip).
    """
    allowed = tuple(allowed_doc_types)

    if not isinstance(cve_id, str) or not cve_id.strip():
        raise ValueError("RAGDocument validation failed: cve_id is empty or not a string.")

    if doc_type not in allowed:
        raise ValueError(
            "RAGDocument validation failed: doc_type is invalid. "
            f"Got '{doc_type}', allowed={allowed}. "
            "Update Resources.DOC_TYPES if you intend to support a new document type."
        )

    if not isinstance(text, str) or not text.strip():
        raise ValueError(
            "RAGDocument validation failed: text is empty. "
            f"(cve_id={cve_id}, doc_type={doc_type})"
        )

    # Ensure metadata always includes doc_type + cve_id for traceability
    md = dict(metadata)
    md.setdefault("cve_id", cve_id)
    md.setdefault("doc_type", doc_type)

    return RAGDocument(cve_id=cve_id, doc_type=doc_type, text=text, metadata=md)