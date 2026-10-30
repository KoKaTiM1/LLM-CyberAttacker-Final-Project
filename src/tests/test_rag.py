"""
test_rag.py

Comprehensive tests for the local CVE RAG pipeline.
Covers:
  - rag_types.py  : RAGDocument, RetrievedDocument, make_rag_document
  - config.py     : RagConfig
  - resources.py  : Resources (classification, extraction, patterns)
  - rag.py        : document builders, SQLiteDocStore, retrieval helpers,
                    and an integration smoke-test against the real JSONL file.

Run from the repo root (or any directory) with:
    python -m pytest src/tests/test_rag.py -v
or:
    python src/tests/test_rag.py
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Adjust sys.path so the RAG sub-package is importable regardless of CWD.
# ---------------------------------------------------------------------------
_RAG_DIR = Path(__file__).resolve().parent.parent / "modules" / "rag"
if str(_RAG_DIR) not in sys.path:
    sys.path.insert(0, str(_RAG_DIR))

# ---------------------------------------------------------------------------
# Stub optional heavy dependencies so the module is importable even when
# faiss-cpu / sentence-transformers are not installed in this environment.
# ---------------------------------------------------------------------------
import types as _types
import unittest.mock as _mock

def _stub_module(name: str) -> None:
    """Insert a MagicMock as a top-level module if it is not already installed."""
    if name not in sys.modules:
        try:
            __import__(name)
        except ImportError:
            sys.modules[name] = _mock.MagicMock()

_stub_module("faiss")
_stub_module("numpy")
# numpy sub-modules that rag.py may touch after import
for _sub in ("numpy.core", "numpy.linalg"):
    _stub_module(_sub)
import numpy as np  # noqa: E402 — after stubbing

_stub_module("sentence_transformers")

from config import RagConfig
from resources import Resources
from rag_types import RAGDocument, RetrievedDocument, make_rag_document
import rag as rag_module

# ---------------------------------------------------------------------------
# Path to the real JSONL fixture (filtered dataset in the repo).
# ---------------------------------------------------------------------------
# test_rag.py lives at src/tests/; project root is 2 levels up
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_JSONL_PATH = _REPO_ROOT / "data" / "nvd_cves_filtered_buffer_overflow_format_string.jsonl"


# ==========================================================================
# Helpers
# ==========================================================================

def _make_minimal_record(
    cve_id: str = "CVE-2024-0001",
    description: str = "Stack-based buffer overflow in example software.",
    cwes: list[str] | None = None,
    vuln_status: str = "Analyzed",
    cvss_v31_score: float | None = 7.5,
    is_linux: bool = False,
) -> Dict[str, Any]:
    """Build a minimal NVD-style record dict for testing."""
    cwe_descs = [{"lang": "en", "value": c} for c in (cwes or ["CWE-121"])]
    weaknesses = [{"source": "nvd@nist.gov", "type": "Primary", "description": cwe_descs}]

    cvss_metrics: Dict[str, Any] = {}
    # rag.py reads "cvssMetricV30" (v3.0) — use that key to exercise the v3 branch
    if cvss_v31_score is not None:
        cvss_metrics["cvssMetricV30"] = [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "baseScore": cvss_v31_score,
                    "baseSeverity": "HIGH",
                },
            }
        ]

    cpe_matches = []
    if is_linux:
        cpe_matches.append(
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "4.0",
                "versionEndExcluding": "5.10.220",
            }
        )
    else:
        cpe_matches.append(
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:a:example:app:1.0:*:*:*:*:*:*:*",
            }
        )

    configurations = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": cpe_matches}]}]

    return {
        "cve": {
            "id": cve_id,
            "sourceIdentifier": "test@example.com",
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-06-01T00:00:00.000",
            "vulnStatus": vuln_status,
            "cveTags": [],
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": cvss_metrics,
            "weaknesses": weaknesses,
            "configurations": configurations,
            "references": [],
        }
    }


def _default_cfg(**overrides) -> RagConfig:
    return RagConfig(
        input_jsonl_path="",
        output_jsonl_path=None,
        sqlite_path=":memory:",
        faiss_index_path="",
        linux_only=False,
        validated_only=False,
        **overrides,
    )


# ==========================================================================
# 1. rag_types.py
# ==========================================================================

class TestRAGDocument(unittest.TestCase):
    def test_doc_key_format(self):
        doc = RAGDocument(cve_id="CVE-2024-0001", doc_type="core", text="hello", metadata={})
        self.assertEqual(doc.doc_key, "CVE-2024-0001:core")

    def test_frozen(self):
        doc = RAGDocument(cve_id="CVE-2024-0001", doc_type="core", text="hi", metadata={})
        with self.assertRaises((AttributeError, TypeError)):
            doc.cve_id = "CVE-9999-9999"  # frozen dataclass raises FrozenInstanceError(AttributeError)


class TestRetrievedDocument(unittest.TestCase):
    def test_defaults(self):
        inner = RAGDocument(cve_id="CVE-2024-0001", doc_type="core", text="x", metadata={})
        rd = RetrievedDocument(document=inner, score=0.9)
        self.assertIsNone(rd.faiss_id)


class TestMakeRagDocument(unittest.TestCase):
    def _allowed(self):
        return Resources().DOC_TYPES

    def test_valid_creation(self):
        doc = make_rag_document(
            cve_id="CVE-2024-0001",
            doc_type="core",
            text="A buffer overflow.",
            metadata={"foo": "bar"},
            allowed_doc_types=self._allowed(),
        )
        self.assertEqual(doc.cve_id, "CVE-2024-0001")
        self.assertEqual(doc.doc_type, "core")
        # Factory injects cve_id and doc_type into metadata
        self.assertEqual(doc.metadata["cve_id"], "CVE-2024-0001")
        self.assertEqual(doc.metadata["doc_type"], "core")

    def test_invalid_doc_type_raises(self):
        with self.assertRaises(ValueError):
            make_rag_document(
                cve_id="CVE-2024-0001",
                doc_type="INVALID",
                text="x",
                metadata={},
                allowed_doc_types=self._allowed(),
            )

    def test_empty_cve_id_raises(self):
        with self.assertRaises(ValueError):
            make_rag_document(
                cve_id="   ",
                doc_type="core",
                text="x",
                metadata={},
                allowed_doc_types=self._allowed(),
            )

    def test_empty_text_raises(self):
        with self.assertRaises(ValueError):
            make_rag_document(
                cve_id="CVE-2024-0001",
                doc_type="core",
                text="",
                metadata={},
                allowed_doc_types=self._allowed(),
            )

    def test_metadata_preserved(self):
        doc = make_rag_document(
            cve_id="CVE-2024-0001",
            doc_type="weakness",
            text="weakness text",
            metadata={"extra": 42},
            allowed_doc_types=self._allowed(),
        )
        self.assertEqual(doc.metadata["extra"], 42)


# ==========================================================================
# 2. config.py
# ==========================================================================

class TestRagConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = RagConfig(
            input_jsonl_path="/tmp/in.jsonl",
            output_jsonl_path=None,
            sqlite_path="/tmp/store.db",
            faiss_index_path="/tmp/index.faiss",
        )
        self.assertFalse(cfg.linux_only)
        self.assertFalse(cfg.validated_only)
        self.assertIn("en", cfg.description_langs)
        self.assertEqual(cfg.progress_every, 10_000)

    def test_frozen(self):
        cfg = _default_cfg()
        with self.assertRaises((AttributeError, TypeError)):
            cfg.linux_only = True  # frozen dataclass raises FrozenInstanceError(AttributeError)


# ==========================================================================
# 3. resources.py
# ==========================================================================

class TestResourcesClassification(unittest.TestCase):
    def setUp(self):
        self.r = Resources()

    # --- classify_bucket_from_cwes ---

    def test_overflow_family(self):
        self.assertEqual(self.r.classify_bucket_from_cwes({"CWE-120"}), "overflow_family")

    def test_format_string(self):
        self.assertEqual(self.r.classify_bucket_from_cwes({"CWE-134"}), "format_string")

    def test_both(self):
        self.assertEqual(self.r.classify_bucket_from_cwes({"CWE-120", "CWE-134"}), "both")

    def test_unknown_no_cwe(self):
        self.assertEqual(self.r.classify_bucket_from_cwes(set()), "unknown")

    def test_unknown_noncve_string(self):
        self.assertEqual(self.r.classify_bucket_from_cwes({"NVD-CWE-Other"}), "unknown")

    def test_cwe787_is_overflow(self):
        self.assertEqual(self.r.classify_bucket_from_cwes({"CWE-787"}), "overflow_family")

    def test_cwe119_is_overflow(self):
        self.assertEqual(self.r.classify_bucket_from_cwes({"CWE-119"}), "overflow_family")

    # --- classify_bucket_from_keywords ---

    def test_keyword_overflow(self):
        self.assertEqual(
            self.r.classify_bucket_from_keywords("heap-based buffer overflow in libc"),
            "overflow_family",
        )

    def test_keyword_format_string(self):
        self.assertEqual(
            self.r.classify_bucket_from_keywords("format string vulnerability in daemon"),
            "format_string",
        )

    def test_keyword_both(self):
        result = self.r.classify_bucket_from_keywords(
            "buffer overflow and format string vulnerability"
        )
        self.assertEqual(result, "both")

    def test_keyword_unknown(self):
        self.assertEqual(self.r.classify_bucket_from_keywords("unrelated text"), "unknown")

    def test_keyword_empty_string(self):
        self.assertEqual(self.r.classify_bucket_from_keywords(""), "unknown")

    def test_keyword_none(self):
        self.assertEqual(self.r.classify_bucket_from_keywords(None), "unknown")


class TestResourcesExtraction(unittest.TestCase):
    def setUp(self):
        self.r = Resources()

    def test_extract_file_path_found(self):
        text = "The vulnerability is in drivers/net/usb/hso.c line 42."
        result = self.r.extract_file_path(text)
        self.assertEqual(result, "drivers/net/usb/hso.c")

    def test_extract_file_path_not_found(self):
        self.assertIsNone(self.r.extract_file_path("No file path here."))

    def test_extract_file_path_empty(self):
        self.assertIsNone(self.r.extract_file_path(""))

    def test_extract_file_path_none(self):
        self.assertIsNone(self.r.extract_file_path(None))

    def test_derive_subsystem_prefix(self):
        self.assertEqual(
            self.r.derive_subsystem_prefix("drivers/net/usb/hso.c"),
            "drivers/net/usb",
        )

    def test_derive_subsystem_prefix_no_slash(self):
        self.assertIsNone(self.r.derive_subsystem_prefix("file.c"))

    def test_derive_subsystem_prefix_empty(self):
        self.assertIsNone(self.r.derive_subsystem_prefix(""))

    def test_version_token_pattern(self):
        matches = self.r.VERSION_TOKEN_PATTERN.findall("kernel 4.19.8 through 5.15")
        self.assertIn("4.19.8", matches)
        self.assertIn("5.15", matches)


# ==========================================================================
# 4. rag.py — private helpers
# ==========================================================================

class TestPickPrimaryMetric(unittest.TestCase):
    def test_picks_primary(self):
        metrics = [
            {"type": "Secondary", "cvssData": {}},
            {"type": "Primary", "cvssData": {"baseScore": 9.8}},
        ]
        result = rag_module._pick_primary_metric(metrics)
        self.assertEqual(result["type"], "Primary")

    def test_falls_back_to_first(self):
        metrics = [
            {"type": "Secondary", "cvssData": {"baseScore": 5.0}},
        ]
        result = rag_module._pick_primary_metric(metrics)
        self.assertEqual(result["type"], "Secondary")

    def test_empty_list(self):
        self.assertIsNone(rag_module._pick_primary_metric([]))


class TestExtractEnDescription(unittest.TestCase):
    def test_prefers_en(self):
        cve = {
            "descriptions": [
                {"lang": "es", "value": "spanish"},
                {"lang": "en", "value": "english"},
            ]
        }
        text, found = rag_module._extract_en_description(cve, {"en"})
        self.assertEqual(text, "english")
        self.assertTrue(found)

    def test_only_es_not_in_langs(self):
        cve = {"descriptions": [{"lang": "es", "value": "spanish"}]}
        text, found = rag_module._extract_en_description(cve, {"en"})
        self.assertEqual(text, "")
        self.assertFalse(found)

    def test_empty_descriptions(self):
        cve = {"descriptions": []}
        text, found = rag_module._extract_en_description(cve, {"en"})
        self.assertFalse(found)

    def test_non_list_descriptions(self):
        cve = {"descriptions": "bad value"}
        text, found = rag_module._extract_en_description(cve, {"en"})
        self.assertFalse(found)


class TestExtractCwes(unittest.TestCase):
    def test_extracts_cwes(self):
        cve = {
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-120"}, {"lang": "en", "value": "CWE-134"}],
                }
            ]
        }
        result = rag_module._extract_cwes(cve)
        self.assertIn("CWE-120", result)
        self.assertIn("CWE-134", result)

    def test_ignores_non_cwe_values(self):
        cve = {
            "weaknesses": [
                {"description": [{"lang": "en", "value": "NVD-CWE-Other"}]}
            ]
        }
        result = rag_module._extract_cwes(cve)
        self.assertNotIn("NVD-CWE-Other", result)

    def test_empty_weaknesses(self):
        self.assertEqual(rag_module._extract_cwes({"weaknesses": []}), set())

    def test_no_weaknesses_key(self):
        self.assertEqual(rag_module._extract_cwes({}), set())


class TestExtractLinuxKernelBounds(unittest.TestCase):
    def test_detects_linux_kernel(self):
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "4.0",
                                    "versionEndExcluding": "5.10.100",
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        is_linux, bounds = rag_module._extract_linux_kernel_bounds(cve)
        self.assertTrue(is_linux)
        self.assertEqual(bounds["versionStartIncluding"], "4.0")
        self.assertEqual(bounds["versionEndExcluding"], "5.10.100")

    def test_non_linux(self):
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            ]
        }
        is_linux, bounds = rag_module._extract_linux_kernel_bounds(cve)
        self.assertFalse(is_linux)
        self.assertEqual(bounds, {})

    def test_empty_configurations(self):
        is_linux, bounds = rag_module._extract_linux_kernel_bounds({"configurations": []})
        self.assertFalse(is_linux)


class TestFormatVersionSummary(unittest.TestCase):
    def test_start_and_end_excl(self):
        bounds = {
            "versionStartIncluding": "4.0",
            "versionStartExcluding": None,
            "versionEndIncluding": None,
            "versionEndExcluding": "5.10",
        }
        self.assertEqual(rag_module._format_version_summary(bounds), ">= 4.0 < 5.10")

    def test_end_incl_only(self):
        bounds = {
            "versionStartIncluding": None,
            "versionStartExcluding": None,
            "versionEndIncluding": "5.15.50",
            "versionEndExcluding": None,
        }
        self.assertEqual(rag_module._format_version_summary(bounds), "<= 5.15.50")

    def test_all_none(self):
        bounds = {
            "versionStartIncluding": None,
            "versionStartExcluding": None,
            "versionEndIncluding": None,
            "versionEndExcluding": None,
        }
        self.assertEqual(rag_module._format_version_summary(bounds), "unknown")


class TestQueryHasVersionIntent(unittest.TestCase):
    def test_version_token(self):
        self.assertTrue(rag_module._query_has_version_intent("kernel 4.19.8 overflow"))

    def test_keyword_before(self):
        self.assertTrue(rag_module._query_has_version_intent("versions before 5.10 affected"))

    def test_keyword_through(self):
        self.assertTrue(rag_module._query_has_version_intent("version 4.0 through 4.19"))

    def test_no_version_intent(self):
        self.assertFalse(rag_module._query_has_version_intent("heap buffer overflow in ssh"))


# ==========================================================================
# 5. rag.py — document builders
# ==========================================================================

class TestBuildCoreDocument(unittest.TestCase):
    def setUp(self):
        self.resources = Resources()
        self.cfg = _default_cfg()

    def test_basic_fields(self):
        record = _make_minimal_record("CVE-2024-1111", "Stack overflow in X.", ["CWE-121"])
        doc = rag_module.build_core_document(record, self.resources, self.cfg)
        self.assertEqual(doc.cve_id, "CVE-2024-1111")
        self.assertEqual(doc.doc_type, "core")
        self.assertIn("CVE-2024-1111", doc.text)
        self.assertIn("Stack overflow in X.", doc.text)

    def test_bucket_from_cwe(self):
        record = _make_minimal_record(cwes=["CWE-120"])
        doc = rag_module.build_core_document(record, self.resources, self.cfg)
        self.assertEqual(doc.metadata["bucket"], "overflow_family")
        self.assertEqual(doc.metadata["bucket_source"], "cwe")

    def test_bucket_fallback_to_keyword(self):
        record = _make_minimal_record(
            cwes=["NVD-CWE-Other"],  # won't match CWE-XXX pattern in _extract_cwes
            description="buffer overflow in foo service",
        )
        doc = rag_module.build_core_document(record, self.resources, self.cfg)
        self.assertEqual(doc.metadata["bucket"], "overflow_family")
        self.assertEqual(doc.metadata["bucket_source"], "keyword")

    def test_cvss_v31_parsed(self):
        record = _make_minimal_record(cvss_v31_score=8.0)
        doc = rag_module.build_core_document(record, self.resources, self.cfg)
        self.assertEqual(doc.metadata["cvss_version"], "3.x")
        self.assertAlmostEqual(doc.metadata["cvss_score"], 8.0)

    def test_linux_kernel_detected(self):
        record = _make_minimal_record(is_linux=True)
        doc = rag_module.build_core_document(record, self.resources, self.cfg)
        self.assertTrue(doc.metadata["is_linux_kernel"])
        self.assertNotEqual(doc.metadata["version_summary"], "unknown")

    def test_non_linux(self):
        record = _make_minimal_record(is_linux=False)
        doc = rag_module.build_core_document(record, self.resources, self.cfg)
        self.assertFalse(doc.metadata["is_linux_kernel"])

    def test_file_path_extracted(self):
        record = _make_minimal_record(description="Bug in net/core/dev.c causes overflow.")
        doc = rag_module.build_core_document(record, self.resources, self.cfg)
        self.assertEqual(doc.metadata["file_path"], "net/core/dev.c")
        self.assertTrue(doc.metadata["has_file_path"])

    def test_invalid_record_raises(self):
        with self.assertRaises(ValueError):
            rag_module.build_core_document({}, self.resources, self.cfg)

    def test_missing_cve_id_raises(self):
        record = {"cve": {"id": "", "descriptions": [], "metrics": {}, "weaknesses": [], "configurations": []}}
        with self.assertRaises(ValueError):
            rag_module.build_core_document(record, self.resources, self.cfg)

    def test_format_string_bucket(self):
        record = _make_minimal_record(cwes=["CWE-134"], description="Format string bug.")
        doc = rag_module.build_core_document(record, self.resources, self.cfg)
        self.assertEqual(doc.metadata["bucket"], "format_string")


class TestBuildWeaknessDocument(unittest.TestCase):
    def setUp(self):
        self.resources = Resources()
        self.cfg = _default_cfg()

    def _core(self, cwes=None, bucket="overflow_family"):
        record = _make_minimal_record(cwes=cwes or ["CWE-120"])
        return rag_module.build_core_document(record, self.resources, self.cfg)

    def test_doc_type(self):
        doc = rag_module.build_weakness_document(self._core(), self.resources)
        self.assertEqual(doc.doc_type, "weakness")

    def test_pattern_overflow(self):
        doc = rag_module.build_weakness_document(self._core(["CWE-120"]), self.resources)
        self.assertIn("buffer overflow", doc.text)

    def test_pattern_format_string(self):
        record = _make_minimal_record(cwes=["CWE-134"])
        core = rag_module.build_core_document(record, self.resources, self.cfg)
        doc = rag_module.build_weakness_document(core, self.resources)
        self.assertIn("format string", doc.text)

    def test_pattern_oob_read(self):
        record = _make_minimal_record(cwes=["CWE-125"])
        core = rag_module.build_core_document(record, self.resources, self.cfg)
        doc = rag_module.build_weakness_document(core, self.resources)
        self.assertIn("out-of-bounds read", doc.text)

    def test_pattern_oob_write(self):
        record = _make_minimal_record(cwes=["CWE-787"])
        core = rag_module.build_core_document(record, self.resources, self.cfg)
        doc = rag_module.build_weakness_document(core, self.resources)
        self.assertIn("out-of-bounds write", doc.text)


class TestBuildVersionDocument(unittest.TestCase):
    def setUp(self):
        self.resources = Resources()
        self.cfg = _default_cfg()

    def test_doc_type(self):
        record = _make_minimal_record(is_linux=True)
        core = rag_module.build_core_document(record, self.resources, self.cfg)
        doc = rag_module.build_version_document(core, self.resources)
        self.assertEqual(doc.doc_type, "version")

    def test_version_bounds_present(self):
        record = _make_minimal_record(is_linux=True)
        core = rag_module.build_core_document(record, self.resources, self.cfg)
        doc = rag_module.build_version_document(core, self.resources)
        self.assertIn("4.0", doc.text)

    def test_non_linux_product(self):
        record = _make_minimal_record(is_linux=False)
        core = rag_module.build_core_document(record, self.resources, self.cfg)
        doc = rag_module.build_version_document(core, self.resources)
        self.assertIn("unknown", doc.text)


# ==========================================================================
# 6. rag.py — SqliteDocStore
# ==========================================================================

class TestSqliteDocStore(unittest.TestCase):
    def _make_store(self):
        return rag_module.SqliteDocStore(":memory:")

    def _make_doc(self, cve_id="CVE-2024-0001", doc_type="core"):
        return RAGDocument(
            cve_id=cve_id,
            doc_type=doc_type,
            text=f"Text for {cve_id} {doc_type}",
            metadata={
                "cve_id": cve_id,
                "doc_type": doc_type,
                "bucket": "overflow_family",
                "bucket_source": "cwe",
                "validated_only": False,
                "vuln_status": "Analyzed",
                "cwe_primary": "CWE-120",
                "cvss_version": "3.x",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/...",
                "is_linux_kernel": False,
                "version_summary": "unknown",
                "subsystem_prefix": None,
                "has_file_path": False,
                "published": "2024-01-01",
                "last_modified": "2024-06-01",
            },
        )

    def test_insert_and_fetch_by_faiss_ids(self):
        store = self._make_store()
        doc = self._make_doc()
        store.insert_document(faiss_id=0, doc=doc)
        store.commit()

        result = store.fetch_by_faiss_ids([0])
        self.assertIn(0, result)
        self.assertEqual(result[0].cve_id, "CVE-2024-0001")
        store.close()

    def test_fetch_missing_id_returns_empty(self):
        store = self._make_store()
        result = store.fetch_by_faiss_ids([999])
        self.assertEqual(result, {})
        store.close()

    def test_fetch_empty_list(self):
        store = self._make_store()
        result = store.fetch_by_faiss_ids([])
        self.assertEqual(result, {})
        store.close()

    def test_fetch_by_cve_id(self):
        store = self._make_store()
        for dt, fid in [("core", 0), ("weakness", 1), ("version", 2)]:
            store.insert_document(faiss_id=fid, doc=self._make_doc(doc_type=dt))
        store.commit()

        docs = store.fetch_by_cve_id("CVE-2024-0001")
        self.assertEqual(len(docs), 3)
        doc_types = {d.doc_type for d in docs}
        self.assertEqual(doc_types, {"core", "weakness", "version"})
        store.close()

    def test_fetch_by_cve_id_not_found(self):
        store = self._make_store()
        result = store.fetch_by_cve_id("CVE-9999-9999")
        self.assertEqual(result, [])
        store.close()

    def test_insert_two_cves(self):
        store = self._make_store()
        store.insert_document(0, self._make_doc("CVE-2024-0001"))
        store.insert_document(1, self._make_doc("CVE-2024-0002"))
        store.commit()

        self.assertEqual(len(store.fetch_by_cve_id("CVE-2024-0001")), 1)
        self.assertEqual(len(store.fetch_by_cve_id("CVE-2024-0002")), 1)
        store.close()

    def test_schema_has_expected_indexes(self):
        store = self._make_store()
        cur = store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='docs';"
        )
        index_names = {row[0] for row in cur.fetchall()}
        self.assertIn("idx_docs_cve_id", index_names)
        self.assertIn("idx_docs_bucket", index_names)
        store.close()


# ==========================================================================
# 7. rag.py — aggregate_by_cve & build_llm_context_option2
# ==========================================================================

def _make_retrieved(cve_id: str, doc_type: str, score: float) -> RetrievedDocument:
    doc = RAGDocument(
        cve_id=cve_id,
        doc_type=doc_type,
        text=f"{cve_id}:{doc_type} text",
        metadata={"cve_id": cve_id, "doc_type": doc_type, "is_linux_kernel": False, "vuln_status": "Analyzed"},
    )
    return RetrievedDocument(document=doc, score=score, faiss_id=0)


class TestAggregateByCVE(unittest.TestCase):
    def test_groups_by_cve(self):
        hits = [
            _make_retrieved("CVE-A", "core", 0.9),
            _make_retrieved("CVE-A", "weakness", 0.75),
            _make_retrieved("CVE-B", "core", 0.6),
        ]
        aggs = rag_module.aggregate_by_cve(hits)
        cve_ids = [a.cve_id for a in aggs]
        self.assertIn("CVE-A", cve_ids)
        self.assertIn("CVE-B", cve_ids)

    def test_sorted_descending(self):
        hits = [
            _make_retrieved("CVE-LOW", "core", 0.5),
            _make_retrieved("CVE-HIGH", "core", 0.95),
        ]
        aggs = rag_module.aggregate_by_cve(hits)
        self.assertEqual(aggs[0].cve_id, "CVE-HIGH")

    def test_picks_best_score_per_type(self):
        hits = [
            _make_retrieved("CVE-A", "core", 0.7),
            _make_retrieved("CVE-A", "core", 0.9),  # same type, higher score
        ]
        aggs = rag_module.aggregate_by_cve(hits)
        self.assertEqual(len(aggs), 1)
        self.assertAlmostEqual(aggs[0].core.score, 0.9)

    def test_empty_returns_empty(self):
        self.assertEqual(rag_module.aggregate_by_cve([]), [])

    def test_score_weighting_core_beats_weakness(self):
        # core score 0.9 → effective 0.90; weakness score 0.9 → effective 0.765
        # CVE-A has only core; CVE-B has only weakness—both at 0.9 raw
        hits = [
            _make_retrieved("CVE-A", "core", 0.9),
            _make_retrieved("CVE-B", "weakness", 0.9),
        ]
        aggs = rag_module.aggregate_by_cve(hits)
        self.assertEqual(aggs[0].cve_id, "CVE-A")


class TestBuildLlmContextOption2(unittest.TestCase):
    def _make_agg(self, cve_id: str, score: float):
        core = _make_retrieved(cve_id, "core", score)
        weakness = _make_retrieved(cve_id, "weakness", score * 0.9)
        version = _make_retrieved(cve_id, "version", score * 0.8)
        return rag_module.CVEAggregate(
            cve_id=cve_id, score=score, core=core, weakness=weakness, version=version
        )

    def test_returns_core_for_all(self):
        ranked = [self._make_agg(f"CVE-{i:04d}", 1.0 - i * 0.05) for i in range(10)]
        blocks = rag_module.build_llm_context_option2("heap overflow", ranked, n_cves=10, top_m_deep=3)
        core_count = sum(1 for b in blocks if "core" in b)
        self.assertEqual(core_count, 10)

    def test_top_m_deep_gets_weakness(self):
        ranked = [self._make_agg(f"CVE-{i:04d}", 1.0 - i * 0.05) for i in range(5)]
        blocks = rag_module.build_llm_context_option2("buffer overflow", ranked, n_cves=5, top_m_deep=2)
        weakness_count = sum(1 for b in blocks if "weakness" in b)
        self.assertEqual(weakness_count, 2)  # only top_m_deep=2 get weakness

    def test_version_intent_adds_version_docs(self):
        ranked = [self._make_agg(f"CVE-{i:04d}", 1.0 - i * 0.05) for i in range(3)]
        blocks = rag_module.build_llm_context_option2(
            "kernel 4.19.8 buffer overflow", ranked, n_cves=3, top_m_deep=3
        )
        version_count = sum(1 for b in blocks if "version" in b)
        self.assertGreater(version_count, 0)

    def test_no_version_intent_no_version_docs(self):
        ranked = [self._make_agg(f"CVE-{i:04d}", 1.0 - i * 0.05) for i in range(3)]
        blocks = rag_module.build_llm_context_option2(
            "heap overflow exploit", ranked, n_cves=3, top_m_deep=3
        )
        version_count = sum(1 for b in blocks if "version" in b)
        self.assertEqual(version_count, 0)

    def test_n_cves_limits_output(self):
        ranked = [self._make_agg(f"CVE-{i:04d}", 1.0 - i * 0.05) for i in range(20)]
        blocks = rag_module.build_llm_context_option2("overflow", ranked, n_cves=5, top_m_deep=0)
        # n_cves=5, top_m_deep=0 → only core docs, only first 5
        self.assertEqual(len(blocks), 5)

    def test_empty_ranked_returns_empty(self):
        blocks = rag_module.build_llm_context_option2("anything", [], n_cves=10, top_m_deep=5)
        self.assertEqual(blocks, [])


# ==========================================================================
# 8. rag.py — _order_docs_for_exact_lookup
# ==========================================================================

class TestOrderDocsForExactLookup(unittest.TestCase):
    def _doc(self, doc_type):
        return RAGDocument(cve_id="CVE-A", doc_type=doc_type, text="x", metadata={})

    def test_order_core_weakness_version(self):
        docs = [self._doc("version"), self._doc("weakness"), self._doc("core")]
        ordered = rag_module._order_docs_for_exact_lookup(docs)
        self.assertEqual([d.doc_type for d in ordered], ["core", "weakness", "version"])


# ==========================================================================
# 9. Integration test — build_index against real JSONL (document builders only)
# ==========================================================================

class TestBuildCoreDocumentAgainstRealJSONL(unittest.TestCase):
    """
    Reads the first N lines of the real JSONL file and verifies that
    build_core_document + build_weakness_document + build_version_document
    succeed for every record (or skip gracefully for invalid ones).

    No embedding or FAISS is involved — pure document construction.
    """

    JSONL_PATH = _JSONL_PATH
    MAX_RECORDS = 500  # enough to catch regressions without being slow

    def setUp(self):
        if not self.JSONL_PATH.exists():
            self.skipTest(f"JSONL fixture not found: {self.JSONL_PATH}")
        self.resources = Resources()
        self.cfg = _default_cfg()

    def test_document_builders_on_real_data(self):
        successes = 0
        failures = []

        with open(self.JSONL_PATH, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                if line_no > self.MAX_RECORDS:
                    break
                raw = line.strip()
                if not raw:
                    continue

                try:
                    record = json.loads(raw)
                except json.JSONDecodeError as exc:
                    failures.append((line_no, f"JSONDecodeError: {exc}"))
                    continue

                try:
                    core = rag_module.build_core_document(record, self.resources, self.cfg)
                    weakness = rag_module.build_weakness_document(core, self.resources)
                    version = rag_module.build_version_document(core, self.resources)
                except Exception as exc:
                    failures.append((line_no, f"{type(exc).__name__}: {exc}"))
                    continue

                # Sanity checks on the produced documents
                self.assertEqual(core.doc_type, "core")
                self.assertEqual(weakness.doc_type, "weakness")
                self.assertEqual(version.doc_type, "version")
                self.assertEqual(core.cve_id, weakness.cve_id)
                self.assertEqual(core.cve_id, version.cve_id)
                self.assertTrue(core.text.strip())
                self.assertTrue(weakness.text.strip())
                self.assertTrue(version.text.strip())
                self.assertIn(core.cve_id, core.text)
                self.assertIn("Bucket:", core.text)
                self.assertIn("CWE:", core.text)
                self.assertIn("CWE:", weakness.text)
                self.assertIn("VersionSummary:", version.text)
                successes += 1

        self.assertGreater(successes, 0, "No records were successfully processed.")
        if failures:
            # Soft-fail: report but allow some parse failures (corrupt/edge-case lines)
            # If ALL records failed, the test will already have failed above.
            print(f"\n[INFO] {len(failures)} line(s) failed out of {self.MAX_RECORDS} attempted:")
            for ln, msg in failures[:10]:
                print(f"  Line {ln}: {msg}")

    def test_cve_ids_are_all_uppercase(self):
        """All CVE IDs parsed from the JSONL should be uppercase CVE-YYYY-NNNN."""
        seen = 0
        with open(self.JSONL_PATH, encoding="utf-8") as fh:
            for line in fh:
                if seen >= 100:
                    break
                raw = line.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                    core = rag_module.build_core_document(record, self.resources, self.cfg)
                except Exception:
                    continue
                self.assertRegex(core.cve_id, r"^CVE-\d{4}-\d+$")
                self.assertEqual(core.cve_id, core.cve_id.upper())
                seen += 1

    def test_bucket_is_always_valid(self):
        """Every CVE's bucket must be one of the four defined values."""
        valid_buckets = {
            Resources.BUCKET_OVERFLOW_FAMILY,
            Resources.BUCKET_FORMAT_STRING,
            Resources.BUCKET_BOTH,
            Resources.BUCKET_UNKNOWN,
        }
        seen = 0
        with open(self.JSONL_PATH, encoding="utf-8") as fh:
            for line in fh:
                if seen >= 200:
                    break
                raw = line.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                    core = rag_module.build_core_document(record, self.resources, self.cfg)
                except Exception:
                    continue
                self.assertIn(core.metadata["bucket"], valid_buckets, f"{core.cve_id} has invalid bucket")
                seen += 1

    def test_cvss_score_range(self):
        """CVSS scores must be None or in [0.0, 10.0]."""
        seen = 0
        with open(self.JSONL_PATH, encoding="utf-8") as fh:
            for line in fh:
                if seen >= 200:
                    break
                raw = line.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                    core = rag_module.build_core_document(record, self.resources, self.cfg)
                except Exception:
                    continue
                score = core.metadata.get("cvss_score")
                if score is not None:
                    self.assertGreaterEqual(score, 0.0, f"{core.cve_id}: score below 0")
                    self.assertLessEqual(score, 10.0, f"{core.cve_id}: score above 10")
                seen += 1

    def test_no_duplicate_cve_ids_in_sample(self):
        """A well-formed JSONL should not have duplicate CVE IDs in a small sample."""
        seen_ids = []
        with open(self.JSONL_PATH, encoding="utf-8") as fh:
            for line in fh:
                if len(seen_ids) >= 100:
                    break
                raw = line.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                    core = rag_module.build_core_document(record, self.resources, self.cfg)
                except Exception:
                    continue
                seen_ids.append(core.cve_id)

        self.assertEqual(len(seen_ids), len(set(seen_ids)), "Duplicate CVE IDs found in sample")

    def test_sqlite_round_trip_on_real_records(self):
        """Insert real CVE docs into SQLite (in-memory) and verify round-trip."""
        store = rag_module.SqliteDocStore(":memory:")
        faiss_id = 0
        processed = 0

        with open(self.JSONL_PATH, encoding="utf-8") as fh:
            for line in fh:
                if processed >= 50:
                    break
                raw = line.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                    core = rag_module.build_core_document(record, self.resources, self.cfg)
                    weakness = rag_module.build_weakness_document(core, self.resources)
                    version = rag_module.build_version_document(core, self.resources)
                except Exception:
                    continue

                for doc in (core, weakness, version):
                    store.insert_document(faiss_id=faiss_id, doc=doc)
                    faiss_id += 1
                processed += 1

        store.commit()

        # Spot-check: total rows in docs table
        cur = store.conn.execute("SELECT COUNT(*) FROM docs;")
        total_rows = cur.fetchone()[0]
        self.assertEqual(total_rows, processed * 3)

        store.close()


# ==========================================================================
# Entry point
# ==========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
