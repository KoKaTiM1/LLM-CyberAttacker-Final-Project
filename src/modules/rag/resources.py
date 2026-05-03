"""
resources.py

Purpose:
- Centralize stable constants and compiled patterns used by the RAG pipeline.
- Includes:
  * Document types (core/weakness/version)
  * CWE family definitions (overflow family + format string)
  * Keyword fallback resources (for use when CWE is missing/unusable)
  * Extraction regex patterns (file paths, versions, function markers)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import FrozenSet, Iterable, Optional, Set, Tuple


@dataclass(frozen=True)
class Resources:
    """
    Immutable resources container.

    Notes:
    - Keep all constants stable and deterministic.
    - Avoid storing mutable objects that could be modified mid-run.
    """

    # Document types you will generate per CVE
    DOC_TYPES: Tuple[str, str, str] = ("core", "weakness", "version")

    # Buckets (two vulnerability families at start)
    BUCKET_OVERFLOW_FAMILY: str = "overflow_family"
    BUCKET_FORMAT_STRING: str = "format_string"
    BUCKET_BOTH: str = "both"
    BUCKET_UNKNOWN: str = "unknown"

    # CWE definitions (expanded set per your latest choice, including CWE-787)
    OVERFLOW_FAMILY_CWES: FrozenSet[str] = frozenset(
        {
            "CWE-119",  # Buffer Errors
            "CWE-120",  # Classic Buffer Overflow
            "CWE-121",  # Stack-based Buffer Overflow
            "CWE-122",  # Heap-based Buffer Overflow
            "CWE-123",  # Write-what-where Condition
            "CWE-124",  # Buffer Underwrite ('Buffer Underflow')
            "CWE-125",  # Out-of-bounds Read
            "CWE-126",  # Buffer Over-read
            "CWE-127",  # Buffer Under-read
            "CWE-128",  # Wrap-around Error
            "CWE-129",  # Improper Validation of Array Index
            "CWE-131",  # Incorrect Calculation of Buffer Size
            "CWE-132",  # Incorrect Calculation of Buffer Size for Null-Terminated Strings
            "CWE-133",  # Improper Handling of Insufficiently Terminated Strings
            "CWE-787",  # Out-of-bounds Write
        }
    )

    FORMAT_STRING_CWES: FrozenSet[str] = frozenset(
        {
            "CWE-134",  # Use of Externally-Controlled Format String
        }
    )

    # Keyword fallback resources (used only when CWE is missing/unusable in the first iteration)
    OVERFLOW_KEYWORDS: Tuple[str, ...] = (
        "buffer overflow",
        "buffer overrun",
        "stack-based buffer overflow",
        "heap-based buffer overflow",
        "out-of-bounds read",
        "out-of-bounds write",
        "oob read",
        "oob write",
        "buffer over-read",
        "buffer over-write",
        "over-read",
        "over-write",
    )

    FORMAT_STRING_KEYWORDS: Tuple[str, ...] = (
        "format string",
        "format string vulnerability",
    )

    # Compiled regex patterns (extraction / detection)
    # File paths like: drivers/net/usb/hso.c, net/core/dev.c, fs/ext4/inode.c
    FILE_PATH_PATTERN: re.Pattern = re.compile(
        r"\b(?!\w+://)([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\.(?:c|h|cc|cpp))\b"
    )

    # Function marker pattern: "function <name>"
    FUNCTION_MARKER_PATTERN: re.Pattern = re.compile(
        r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]{2,})\b", re.IGNORECASE
    )

    # Version tokens like 4.19 or 4.19.8 (used later for query intent)
    VERSION_TOKEN_PATTERN: re.Pattern = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")

    def classify_bucket_from_cwes(self, cwe_set: Set[str]) -> str:
        """
        Classify a CVE into a bucket using CWE set intersection.

        Input:
        - cwe_set: set of CWE strings (may be empty)

        Output:
        - "overflow_family", "format_string", "both", or "unknown"
        """
        # Treat CWE as usable only if at least one real CWE id exists
        has_real_cwe = any(isinstance(c, str) and c.startswith("CWE-") for c in cwe_set)
        if not has_real_cwe:
            return self.BUCKET_UNKNOWN

        has_overflow = len(cwe_set.intersection(self.OVERFLOW_FAMILY_CWES)) > 0
        has_format = len(cwe_set.intersection(self.FORMAT_STRING_CWES)) > 0

        if has_overflow and has_format:
            return self.BUCKET_BOTH
        if has_overflow:
            return self.BUCKET_OVERFLOW_FAMILY
        if has_format:
            return self.BUCKET_FORMAT_STRING
        return self.BUCKET_UNKNOWN

    def classify_bucket_from_keywords(self, text: str) -> str:
        """
        Keyword-only classification.

        Intended use (per our plan):
        - Only call this if classify_bucket_from_cwes() returns "unknown".

        Output:
        - "overflow_family", "format_string", "both", or "unknown"
        """
        t = (text or "").lower()

        has_overflow = any(k in t for k in self.OVERFLOW_KEYWORDS)
        has_format = any(k in t for k in self.FORMAT_STRING_KEYWORDS)

        if has_overflow and has_format:
            return self.BUCKET_BOTH
        if has_overflow:
            return self.BUCKET_OVERFLOW_FAMILY
        if has_format:
            return self.BUCKET_FORMAT_STRING
        return self.BUCKET_UNKNOWN

    def extract_file_path(self, text: str) -> Optional[str]:
        """
        Extract the first source-like file path from text.
        Returns None if no match.
        """
        if not text:
            return None
        m = self.FILE_PATH_PATTERN.search(text)
        return m.group(1) if m else None

    def derive_subsystem_prefix(self, file_path: str) -> Optional[str]:
        """
        Derive a subsystem prefix from a file path.
        Example: 'drivers/net/usb/hso.c' -> 'drivers/net/usb'
        """
        if not file_path or "/" not in file_path:
            return None
        return file_path.rsplit("/", 1)[0]