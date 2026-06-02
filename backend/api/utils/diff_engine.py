from __future__ import annotations

import difflib
from typing import Any


def detect_changes(original_text: str, modified_text: str) -> dict[str, Any]:
    """
    Line-based tamper localization for text-like documents.

    Returns:
      - added: list[str]
      - deleted: list[str]
      - modified: list[{from,to}]
    """
    original_lines = original_text.splitlines()
    modified_lines = modified_text.splitlines()

    sm = difflib.SequenceMatcher(a=original_lines, b=modified_lines)
    added: list[str] = []
    deleted: list[str] = []
    modified: list[dict[str, str]] = []

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "insert":
            added.extend(modified_lines[j1:j2])
        elif tag == "delete":
            deleted.extend(original_lines[i1:i2])
        elif tag == "replace":
            a_chunk = original_lines[i1:i2]
            b_chunk = modified_lines[j1:j2]
            # Pair replacements as "modified" as far as possible.
            n = min(len(a_chunk), len(b_chunk))
            for k in range(n):
                modified.append({"from": a_chunk[k], "to": b_chunk[k]})
            # Remaining lines become pure add/delete
            if len(b_chunk) > n:
                added.extend(b_chunk[n:])
            if len(a_chunk) > n:
                deleted.extend(a_chunk[n:])

    return {"added": added, "deleted": deleted, "modified": modified}

