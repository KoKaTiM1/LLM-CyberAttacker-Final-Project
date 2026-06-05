"""
agent_rag.py

Purpose:
- Agentic RAG wrapper using LangGraph.
- Integrates your existing rag.py with LLM decision-making.
- Implements adaptive retrieval, document grading, and question rewriting.

Key Features:
1. LLM decides whether to retrieve or respond directly
2. Grades retrieved documents for relevance
3. Rewrites questions if documents aren't relevant
4. Loops back to retry if needed
5. Returns final answer when confident

Dependencies:
- langgraph
- langchain-core
- Your existing rag.py
"""

from __future__ import annotations
from .model_config import OLLAMA_MODEL, OLLAMA_URL, OLLAMA_TIMEOUT_SECONDS

import os
import re
from typing import Any, Dict, Literal, Optional

from langgraph.graph import StateGraph, START, END
from langchain_core.messages import (
    BaseMessage,
    HumanMessage,
    AIMessage,
    ToolMessage,
)
from langchain_core.tools import tool
from pydantic import BaseModel, Field

# LLM Setup for Ollama (local, no API key needed)
from langchain_ollama import ChatOllama
from ..llm_utils import approximate_token_count, build_langchain_metrics, merge_metric_totals

DEFAULT_OLLAMA_MODEL = os.getenv("RAG_LLM_MODEL", "llama3.2:1b")


def get_llm(model_name: Optional[str] = None):
    """
    Initialize Ollama LLM running locally.
    
    Assumes Ollama is running at: http://localhost:11434
    Note: Make sure Ollama is running before using this!
    """
    return ChatOllama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_URL,
        temperature=0,
        timeout=OLLAMA_TIMEOUT_SECONDS,
    )


# ---------------------------
# State Definition
# ---------------------------

class MessagesState(BaseModel):
    """State for the agentic RAG graph."""
    messages: list[BaseMessage]
    context_blocks: list[str] = Field(default_factory=list)
    selected_cves: list[str] = Field(default_factory=list)
    retrieval_attempted: bool = False
    rewrite_count: int = 0
    max_rewrites: int = 2


def _latest_human_content(messages: list[BaseMessage]) -> str:
    """Return the most recent human question from state messages."""
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage):
            return msg.content
    return messages[0].content if messages else ""


# ---------------------------
# Retriever Tool (wraps your RAG)
# ---------------------------

def create_retriever_tool(
    sqlite_path: str,
    faiss_path: str,
    model_name: str,
    linux_only: bool = True,
    validated_only: bool = True,
    top_k_docs: int = 80,
    n_cves: int = 8,
    top_m_deep: int = 3,
):
    """
    Create a retriever tool that wraps your existing rag.py
    """
    @tool
    def retrieve_cve_docs(query: str) -> str:
        """
        Search and return CVE vulnerability information based on the query.
        Returns structured context with CVE IDs and relevant details.
        """
        try:
            from .rag import call_rag
        except ImportError:
            from rag import call_rag

        result = call_rag(
            user_context=query,
            sqlite_path=sqlite_path,
            faiss_path=faiss_path,
            model_name=model_name,
            linux_only=linux_only,
            validated_only=validated_only,
            top_k_docs=top_k_docs,
            n_cves=n_cves,
            top_m_deep=top_m_deep,
        )
        
        # Package the results
        context_text = "\n\n".join(result["context_blocks"])
        return context_text
    
    return retrieve_cve_docs


# ---------------------------
# Grading Schema
# ---------------------------

class GradeDocuments(BaseModel):
    """Grade whether retrieved documents are relevant to the user question."""
    
    binary_score: str = Field(
        description="Relevance score: 'yes' if documents are relevant, 'no' if not"
    )
    reasoning: str = Field(
        default="",
        description="Brief explanation of the relevance decision"
    )


def _normalize_binary_score(raw: str) -> Literal["yes", "no"]:
    """Normalize noisy model output into yes/no."""
    val = (raw or "").strip().lower()
    if val == "yes":
        return "yes"
    if val == "no":
        return "no"

    # Accept common noisy outputs such as tags or long explanations.
    if re.search(r"\byes\b", val):
        return "yes"
    if re.search(r"\bno\b", val):
        return "no"
    return "no"


# ---------------------------
# LangGraph Nodes
# ---------------------------

def create_agent_rag_graph(
    sqlite_path: str,
    faiss_path: str,
    model_name: str,
    llm_model_name: Optional[str] = None,
    linux_only: bool = True,
    validated_only: bool = True,
    top_k_docs: int = 80,
    n_cves: int = 8,
    top_m_deep: int = 3,
):
    """
    Create the agentic RAG graph with all nodes and edges.
    
    Args:
        sqlite_path: Path to SQLite document store
        faiss_path: Path to FAISS index
        model_name: Sentence-Transformers model for embeddings (e.g., "all-MiniLM-L6-v2")
        linux_only: Filter to Linux kernel CVEs only
        validated_only: Filter to validated CVEs only
    
    Note:
        LLM used: Ollama running locally at http://localhost:11434
        Override the default model by setting RAG_LLM_MODEL or passing get_llm(model_name).
    """
    
    # Initialize LLM and retriever
    llm = get_llm(llm_model_name)
    retriever_tool = create_retriever_tool(
        sqlite_path=sqlite_path,
        faiss_path=faiss_path,
        model_name=model_name,
        linux_only=linux_only,
        validated_only=validated_only,
        top_k_docs=top_k_docs,
        n_cves=n_cves,
        top_m_deep=top_m_deep,
    )
    
    # ==========================================
    # Node 1: Retrieve Context
    # ==========================================
    def retrieve_context(state: MessagesState) -> Dict[str, Any]:
        """
        Always retrieve first, using the user's current question.
        This makes the graph stricter and avoids direct-answer shortcuts.
        """
        user_question = _latest_human_content(state.messages)
        context_text = retriever_tool.invoke({"query": user_question})
        return {
            "messages": state.messages + [
                ToolMessage(
                    content=context_text,
                    tool_call_id="retrieve_cve_docs",
                )
            ],
            "retrieval_attempted": True,
        }
    
    
    # ==========================================
    # Node 2: Grade Documents (Conditional Router)
    # ==========================================
    def grade_documents(state: MessagesState) -> Literal["generate_answer", "rewrite_question"]:
        """
        Determine if the retrieved documents are relevant.
        Routes to either:
        - "generate_answer": If documents are relevant
        - "rewrite_question": If documents are irrelevant or not useful
        """
        # Extract the user question and retrieved content
        user_message = _latest_human_content(state.messages)
        
        # Find the tool response (should be the most recent ToolMessage)
        retrieved_content = ""
        for msg in reversed(state.messages):
            if isinstance(msg, ToolMessage):
                retrieved_content = msg.content
                break
        
        if not retrieved_content:
            return "generate_answer"
        
        # Grade relevance using LLM
        grade_prompt = f"""
You are a grader assessing if retrieved CVE documents are relevant to the user's question.

User Question: {user_message}

Retrieved Document Content:
{retrieved_content[:500]}...

Determine if the retrieved documents contain useful information that answers or relates to the question.
"""
        
        try:
            grade_response = llm.with_structured_output(GradeDocuments).invoke(
                [{"role": "user", "content": grade_prompt}]
            )
            score = _normalize_binary_score(getattr(grade_response, "binary_score", ""))
        except Exception:
            # Fallback for models that fail JSON schema adherence.
            fallback_prompt = (
                "Answer only one token: yes or no. "
                "Are the retrieved CVE documents relevant to the user question?\n\n"
                f"Question: {user_message}\n"
                f"Context: {retrieved_content[:500]}"
            )
            raw = llm.invoke([{"role": "user", "content": fallback_prompt}])
            raw_text = getattr(raw, "content", str(raw))
            score = _normalize_binary_score(raw_text)

        if score == "yes":
            return "generate_answer"
        return "rewrite_question"
    
    
    # ==========================================
    # Node 3: Rewrite Question
    # ==========================================
    def rewrite_question(state: MessagesState) -> Dict[str, Any]:
        """
        If retrieved documents weren't relevant, rewrite the question
        to improve retrieval on the next attempt.
        """
        if state.rewrite_count >= state.max_rewrites:
            # Max rewrites reached - proceed to answer
            return {"messages": state.messages}
        
        original_question = _latest_human_content(state.messages)
        
        rewrite_prompt = f"""
Look at this user question and reformulate it to be better suited for CVE/vulnerability database search.
Make it more specific and include relevant technical terms.

Original question: {original_question}

Provide an improved question that would yield better CVE search results.
"""
        
        improved_response = llm.invoke(
            [{"role": "user", "content": rewrite_prompt}]
        )
        
        # Create new human message with rewritten question
        new_message = HumanMessage(content=improved_response.content)
        
        return {
            "messages": state.messages + [new_message],
            "rewrite_count": state.rewrite_count + 1,
        }

    def route_after_rewrite(state: MessagesState) -> Literal["retrieve", "generate_answer"]:
        """If rewrite budget is exhausted, answer with current context."""
        if state.rewrite_count >= state.max_rewrites:
            return "generate_answer"
        return "retrieve"
    
    
    # ==========================================
    # Node 4: Generate Answer
    # ==========================================
    def generate_answer(state: MessagesState) -> Dict[str, Any]:
        """
        Generate final answer based on retrieved CVE documents.
        """
        user_question = _latest_human_content(state.messages)
        
        # Compile retrieved context
        retrieved_context = ""
        for msg in state.messages:
            if isinstance(msg, ToolMessage):
                retrieved_context += msg.content + "\n"
        
        answer_prompt = f"""
You are a cybersecurity expert helping with vulnerability analysis.

User Question: {user_question}

Retrieved CVE Information:
{retrieved_context if retrieved_context else "No specific CVEs were retrieved."}

Provide a clear, concise answer (2-3 sentences max) based on the CVE information if available.
If no relevant CVEs were found, provide general guidance.
"""
        
        final_response = llm.invoke(
            [{"role": "user", "content": answer_prompt}]
        )
        
        return {"messages": state.messages + [final_response]}
    
    
    # ==========================================
    # Build the Graph
    # ==========================================
    workflow = StateGraph(MessagesState)
    
    # Add nodes
    workflow.add_node("retrieve", retrieve_context)
    workflow.add_node("rewrite_question", rewrite_question)
    workflow.add_node("generate_answer", generate_answer)
    
    # Add edges
    workflow.add_edge(START, "retrieve")
    
    # After retrieval: Grade documents
    workflow.add_conditional_edges(
        "retrieve",
        grade_documents,
        {
            "generate_answer": "generate_answer",
            "rewrite_question": "rewrite_question",
        },
    )
    
    # After rewriting: retry retrieval unless rewrite budget is exhausted
    workflow.add_conditional_edges(
        "rewrite_question",
        route_after_rewrite,
        {
            "retrieve": "retrieve",
            "generate_answer": "generate_answer",
        },
    )
    
    # After generating answer: End
    workflow.add_edge("generate_answer", END)
    
    # Compile the graph
    graph = workflow.compile()
    
    return graph


# ---------------------------
# Public API
# ---------------------------

def call_agentic_rag(
    *,
    user_query: str,
    sqlite_path: str,
    faiss_path: str,
    model_name: str,
    llm_model_name: Optional[str] = None,
    linux_only: bool = True,
    validated_only: bool = True,
    top_k_docs: int = 80,
    n_cves: int = 8,
    top_m_deep: int = 3,
) -> Dict[str, Any]:
    """
    Single entry point for the agentic RAG system.
    
    Args:
        user_query: The user's question about CVEs
        sqlite_path: Path to SQLite document store
        faiss_path: Path to FAISS index
        model_name: Sentence-Transformers model name
        llm_model_name: Optional Ollama model name override
        linux_only: Filter to Linux kernel CVEs
        validated_only: Filter to validated CVEs
        top_k_docs: FAISS top-k documents for retrieval
        n_cves: Number of CVEs selected for context
        top_m_deep: Number of CVEs with extra weakness/version context
    
    Returns:
        Dict with:
        - "final_answer": The agent's final response
        - "messages": Full conversation history
        - "conversation_length": Number of steps taken
    
    Note:
        Uses Ollama running locally at http://localhost:11434
        Default model comes from RAG_LLM_MODEL or gpt-oss:20b.
    """
    
    # Create the graph
    graph = create_agent_rag_graph(
        sqlite_path=sqlite_path,
        faiss_path=faiss_path,
        model_name=model_name,
        llm_model_name=llm_model_name,
        linux_only=linux_only,
        validated_only=validated_only,
        top_k_docs=top_k_docs,
        n_cves=n_cves,
        top_m_deep=top_m_deep,
    )
    
    # Initialize state with user query
    initial_state = MessagesState(
        messages=[HumanMessage(content=user_query)],
    )
    
    # Run the graph
    final_state = graph.invoke(initial_state)

    # Extract final answer
    final_answer = ""
    rag_context_text = ""
    metrics_total: Dict[str, Any] = {}
    final_answer_metrics: Dict[str, Any] = {}
    if isinstance(final_state, dict):
        messages = final_state.get("messages", [])
    else:
        messages = getattr(final_state, "messages", [])

    for msg in messages:
        if isinstance(msg, AIMessage):
            final_answer = msg.content
            metric = build_langchain_metrics(
                stage="rag_llm_step",
                model=llm_model_name or DEFAULT_OLLAMA_MODEL,
                response_text=msg.content,
                message=msg,
            )
            metrics_total = merge_metric_totals(metrics_total, metric)
            final_answer_metrics = metric
        elif isinstance(msg, ToolMessage):
            rag_context_text += f"{msg.content}\n"

    rag_context_tokens = approximate_token_count(rag_context_text)
    query_tokens = approximate_token_count(user_query)
    rag_metrics = {
        "query_tokens": query_tokens,
        "retrieved_context_tokens": rag_context_tokens,
        "answer_tokens": final_answer_metrics.get("response_tokens", 0),
        "tokens_per_second": final_answer_metrics.get("tokens_per_second", 0),
        "model": llm_model_name or DEFAULT_OLLAMA_MODEL,
        "prompt_tokens": final_answer_metrics.get("prompt_tokens", 0),
        "response_tokens": metrics_total.get("response_tokens", 0),
        "total_context_tokens": final_answer_metrics.get("total_context_tokens", 0),
        "llm_totals": metrics_total,
    }
    
    return {
        "final_answer": final_answer,
        "messages": messages,
        "conversation_length": len(messages),
        "metrics": rag_metrics,
    }


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python agent_rag.py '<query>'")
        print("Example: python agent_rag.py 'Format string vulnerabilities in Linux kernel'")
        sys.exit(1)
    
    query = sys.argv[1]
    
    result = call_agentic_rag(
        user_query=query,
        sqlite_path="data/cve.db",
        faiss_path="data/cve.index",
        model_name="all-MiniLM-L6-v2",
    )
    
    print("\n" + "="*60)
    print("AGENTIC RAG RESPONSE")
    print("="*60)
    print(result["final_answer"])
    print(f"\nConversation steps: {result['conversation_length']}")
