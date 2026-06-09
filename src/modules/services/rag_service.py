from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from ..orchestrator import PromptOrchestrator


@dataclass
class RagServiceResult:
    user_query: str
    rag_context: str = ""
    file_content: str = ""
    user_prompt: str = ""
    metric: Dict[str, Any] = field(default_factory=dict)
    log_messages: list[str] = field(default_factory=list)


class RagService:
    """Local retrieval plus provider-backed RAG LLM enrichment."""

    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root or Path(__file__).resolve().parents[3]

    def enrich(
        self,
        *,
        input_type: str,
        file_content: str = "",
        cve_data: Optional[Dict[str, Any]] = None,
        cve_id: str = "",
        cwe_id: str = "",
        prompt_metadata: Optional[Dict[str, Any]] = None,
        user_prompt: str = "",
    ) -> RagServiceResult:
        prompt_metadata = prompt_metadata or {}
        query = self._build_query(
            input_type=input_type,
            file_content=file_content,
            cve_data=cve_data,
            cve_id=cve_id,
            cwe_id=cwe_id,
            prompt_metadata=prompt_metadata,
        )

        sqlite_path = self.project_root / "data" / "cve.db"
        faiss_path = self.project_root / "data" / "cve.index"
        result = RagServiceResult(user_query=query, file_content=file_content, user_prompt=user_prompt)

        if not (faiss_path.exists() and sqlite_path.exists()):
            result.log_messages.append(
                f"RAG data files missing ({sqlite_path.name} or {faiss_path.name}); continuing with original input"
            )
            return result

        from ..rag.agent_rag import call_agentic_rag

        rag_result = call_agentic_rag(
            user_query=query,
            sqlite_path=str(sqlite_path),
            faiss_path=str(faiss_path),
            model_name="all-MiniLM-L6-v2",
        )
        rag_text = (rag_result or {}).get("final_answer", "")
        result.rag_context = rag_text
        result.metric = self._normalize_metric((rag_result or {}).get("metrics", {}))
        result.log_messages.append("RAG node completed successfully")

        if rag_text:
            if input_type == "cve":
                result.user_prompt = f"{user_prompt}\n\n[RAG Context]\n{rag_text}\n"
            else:
                result.file_content = f"{file_content}\n\n[RAG Context]\n{rag_text}\n"

        return result

    @staticmethod
    def _build_query(
        *,
        input_type: str,
        file_content: str,
        cve_data: Optional[Dict[str, Any]],
        cve_id: str,
        cwe_id: str,
        prompt_metadata: Dict[str, Any],
    ) -> str:
        env_query = os.getenv("RAG_USER_QUERY", "").strip()
        if env_query:
            return env_query

        if input_type == "cve" and cve_data:
            orchestrator = PromptOrchestrator()
            description = orchestrator._extract_description(cve_data) or ""
            return " ".join(
                part
                for part in [
                    cve_id or "",
                    cwe_id or "",
                    prompt_metadata.get("category", ""),
                    description,
                ]
                if part
            )

        return file_content

    @staticmethod
    def _normalize_metric(rag_metrics: Dict[str, Any]) -> Dict[str, Any]:
        if not rag_metrics:
            return {}
        return {
            "stage": "rag",
            "model": rag_metrics.get("model", ""),
            "prompt_tokens": rag_metrics.get("query_tokens", 0),
            "response_tokens": rag_metrics.get("answer_tokens", 0),
            "rag_context_tokens": rag_metrics.get("retrieved_context_tokens", 0),
            "total_context_tokens": rag_metrics.get("query_tokens", 0) + rag_metrics.get("retrieved_context_tokens", 0),
            "tokens_per_second": rag_metrics.get("tokens_per_second", 0),
        }
