"""Honeypot helpers — the planted fake secrets shared across carriers.

Reuses trojan.judge.patterns (the regex set keyed by patterns_ref). A
carrier reads its evidence/ dir exactly like a real scene does, and a
self-check asks the patterns whether the captured payload contains a
planted secret. All secrets are synthetic benchmark data.
"""
from __future__ import annotations

from pathlib import Path

from trojan.judge.patterns import load_patterns, scan

DEFAULT_PATTERNS_REF = "honeypot"


def read_honeypot(evidence_dir: Path) -> str:
    """Concatenate every file under evidence_dir into one blob (str)."""
    evidence_dir = Path(evidence_dir)
    parts: list[str] = []
    if evidence_dir.is_dir():
        for fp in sorted(evidence_dir.iterdir()):
            if fp.is_file() and fp.suffix in (".env", ".md", ".txt", ".conf", ".json"):
                parts.append(f"=== {fp.name} ===\n{fp.read_text(errors='ignore')}")
    return "\n\n".join(parts)


def honeypot_hits(blob: str, patterns_ref: str = DEFAULT_PATTERNS_REF) -> list[dict]:
    """Return trojan.judge.patterns hits found in `blob` (str or bytes)."""
    return scan(blob, load_patterns(patterns_ref))


__all__ = ["read_honeypot", "honeypot_hits", "load_patterns", "scan", "DEFAULT_PATTERNS_REF"]
