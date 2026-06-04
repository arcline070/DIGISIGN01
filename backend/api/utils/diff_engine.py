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
                modified.append({"old": a_chunk[k], "new": b_chunk[k]})
            # Remaining lines become pure add/delete
            if len(b_chunk) > n:
                added.extend(b_chunk[n:])
            if len(a_chunk) > n:
                deleted.extend(a_chunk[n:])

    return {"added": added, "deleted": deleted, "modified": modified}


def localize_tampering(original, tampered, path=""):
    changes = {"added": {}, "deleted": {}, "modified": {}}
    
    if isinstance(original, dict) and isinstance(tampered, dict):
        # Check for deleted and modified fields
        for key, old_value in original.items():
            current_path = f"{path}.{key}" if path else str(key)
            if key not in tampered:
                changes["deleted"][current_path] = old_value
            else:
                nested = localize_tampering(old_value, tampered[key], current_path)
                changes["added"].update(nested["added"])
                changes["deleted"].update(nested["deleted"])
                changes["modified"].update(nested["modified"])
                
        # Check for newly added fields
        for key, new_value in tampered.items():
            current_path = f"{path}.{key}" if path else str(key)
            if key not in original:
                changes["added"][current_path] = new_value

    elif isinstance(original, list) and isinstance(tampered, list):
        # Compare arrays by index
        max_len = max(len(original), len(tampered))
        for i in range(max_len):
            current_path = f"{path}[{i}]"
            if i >= len(tampered):
                changes["deleted"][current_path] = original[i]
            elif i >= len(original):
                changes["added"][current_path] = tampered[i]
            else:
                nested = localize_tampering(original[i], tampered[i], current_path)
                changes["added"].update(nested["added"])
                changes["deleted"].update(nested["deleted"])
                changes["modified"].update(nested["modified"])
    else:
        # Base case: compare primitive values (strings, ints, booleans)
        if original != tampered:
            # Reconcile Excel float vs ISO string comparison
            if isinstance(original, str) and isinstance(tampered, float):
                try:
                    import pandas as pd
                    dt = pd.to_datetime(tampered, unit='D', origin='1899-12-30')
                    val = dt.isoformat()
                    if '+' not in val and not val.endswith('Z'):
                        if '.' not in val: val += '.000'
                        val += 'Z'
                    print(f"[DIFF_DEBUG] original='{original}' val='{val}' match={val == original}")
                    if val == original:
                        return changes
                except Exception as e:
                    print(f"[DIFF_DEBUG] error reconciling: {e}")
                    pass
            changes["modified"][path] = {"old": original, "new": tampered}
            
    return changes
