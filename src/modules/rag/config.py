"""
Purpose:
- Centralized runtime configuration for the local CVE RAG pipeline.
- Holds user-adjustable knobs (paths, scope flags, progress settings).
"""

from dataclasses import dataclass, field
from typing import Optional, Set


@dataclass(frozen=True)
class RagConfig:
    # Paths
    input_jsonl_path: str
    output_jsonl_path: Optional[str]  # Optional: only used if you write a filtered/derived JSONL
    sqlite_path: str
    faiss_index_path: str

    # Scope flags
    linux_only: bool = False
    validated_only: bool = False

    # Text extraction options
    description_langs: Set[str] = field(default_factory=lambda: {"en"})

    # Progress tracking
    progress_every: int = 10_000
