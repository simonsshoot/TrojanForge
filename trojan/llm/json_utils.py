"""Robust JSON extraction from LLM text output.

Four defenses: strip think blocks, direct json.loads, extract
markdown code blocks, then brace-matching scan for the first complete
JSON object.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_CODEBLOCK_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


def strip_think(text: str) -> str:
    """Remove think blocks."""
    return _THINK_RE.sub("", text)


def extract_json(text: str) -> Optional[Any]:
    """Extract a JSON object from LLM text; return None on failure."""
    if not text:
        return None
    cleaned = strip_think(text).strip()

    try:
        return json.loads(cleaned)
    except Exception:
        pass

    m = _CODEBLOCK_RE.search(cleaned)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except Exception:
            pass

    start = cleaned.find("{")
    if start < 0:
        return None
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(cleaned)):
        ch = cleaned[i]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = cleaned[start:i + 1]
                try:
                    return json.loads(candidate)
                except Exception:
                    return None
    return None


def coerce_str_list(value: Any) -> list[str]:
    """Normalize a str-or-list field to list[str]."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(x) for x in value]
    return [str(value)]
