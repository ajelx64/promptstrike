"""OWASP Top 10 for LLM Applications (2025) taxonomy + best-effort CWE mapping.

Titles track the OWASP GenAI Security Project's 2025 list. CWE defaults are provided only where the
mapping is well-established; ambiguous categories map to an empty list so the operator supplies the
CWE explicitly rather than the tool guessing.
"""

from __future__ import annotations

from enum import Enum


class OwaspLLM(str, Enum):
    """OWASP Top 10 for LLM Applications (2025) category identifiers.

    The id is the stable key: probes declare it, findings carry it, and the knowledge pack joins on
    it. Titles live in ``_TITLES`` precisely so OWASP rewording a category does not invalidate
    findings already stored on disk.
    """

    LLM01 = "LLM01"  # Prompt Injection
    LLM02 = "LLM02"  # Sensitive Information Disclosure
    LLM03 = "LLM03"  # Supply Chain
    LLM04 = "LLM04"  # Data and Model Poisoning
    LLM05 = "LLM05"  # Improper Output Handling
    LLM06 = "LLM06"  # Excessive Agency
    LLM07 = "LLM07"  # System Prompt Leakage
    LLM08 = "LLM08"  # Vector and Embedding Weaknesses
    LLM09 = "LLM09"  # Misinformation
    LLM10 = "LLM10"  # Unbounded Consumption


_TITLES: dict[OwaspLLM, str] = {
    OwaspLLM.LLM01: "Prompt Injection",
    OwaspLLM.LLM02: "Sensitive Information Disclosure",
    OwaspLLM.LLM03: "Supply Chain",
    OwaspLLM.LLM04: "Data and Model Poisoning",
    OwaspLLM.LLM05: "Improper Output Handling",
    OwaspLLM.LLM06: "Excessive Agency",
    OwaspLLM.LLM07: "System Prompt Leakage",
    OwaspLLM.LLM08: "Vector and Embedding Weaknesses",
    OwaspLLM.LLM09: "Misinformation",
    OwaspLLM.LLM10: "Unbounded Consumption",
}

# Best-effort defaults; empty list == "operator must supply the CWE".
_DEFAULT_CWES: dict[OwaspLLM, list[str]] = {
    OwaspLLM.LLM01: ["CWE-1427"],          # Improper Neutralization of Input Used for LLM Prompting
    OwaspLLM.LLM02: ["CWE-200"],           # Exposure of Sensitive Information
    OwaspLLM.LLM05: ["CWE-79", "CWE-116"],  # XSS / improper output encoding
    OwaspLLM.LLM06: ["CWE-862", "CWE-250"],  # missing authorization / excessive privilege
    OwaspLLM.LLM07: ["CWE-200", "CWE-540"],  # info exposure / source-of-truth leakage
    OwaspLLM.LLM10: ["CWE-400"],           # Uncontrolled Resource Consumption
}


def title(category: OwaspLLM) -> str:
    """The OWASP-published title for a category, for report headings and CLI output."""
    return _TITLES[category]


def default_cwes(category: OwaspLLM) -> list[str]:
    """Best-effort CWE ids for a category; empty where the mapping is not well established.

    Empty means "the operator supplies the CWE" and is a deliberate outcome, not a gap: a
    confidently wrong CWE in a submitted report costs more credibility than an absent one. Returns
    a copy, so a caller mutating a finding's ``cwe`` list cannot corrupt the shared table.
    """
    return list(_DEFAULT_CWES.get(category, []))
