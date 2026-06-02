"""
Cryptographic utility functions for the immutable hash-chain subsystem.

Vulnerability #5 — Strict Data Canonicalization Mapping
-------------------------------------------------------
``canonicalize_json`` guarantees **bit-exact** JSON serialization regardless of
the ordering of keys, whitespace differences, or floating-point formatting in
the original input.  The pipeline is:

    raw dict/list  →  json.dumps(sort_keys=True, separators=(",",":"),
                                  ensure_ascii=False, allow_nan=False)
                   →  .encode("utf-8")
                   →  hashlib.sha256(...)

``allow_nan=False`` rejects IEEE-754 NaN / Infinity which have no canonical
JSON representation.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Union


# ---------------------------------------------------------------------------
#  Vulnerability #5 — Strict Deterministic Canonicalization
# ---------------------------------------------------------------------------

def canonicalize_json(data: Any) -> str:
    """
    Convert a Python dict/list to a *canonical* JSON string.

    Rules:
      1. Keys sorted recursively (``sort_keys=True``).
      2. No whitespace between tokens (``separators=(",",":")``).
      3. Non-ASCII characters preserved verbatim (``ensure_ascii=False``).
      4. NaN / Infinity rejected          (``allow_nan=False``).
      5. Result is a plain ``str`` ready for ``.encode("utf-8")``.

    Raises ``TypeError`` / ``ValueError`` on non-serializable or NaN input.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonicalize_json_bytes(data: Any) -> bytes:
    """Canonicalize then encode to UTF-8 bytes (ready for SHA-256)."""
    return canonicalize_json(data).encode("utf-8")


def sha256_hex(payload: Union[str, bytes]) -> str:
    """Return the SHA-256 hex digest of *payload* (str → UTF-8 first)."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sha256_bytes(payload: bytes) -> bytes:
    """Return the raw SHA-256 digest bytes."""
    return hashlib.sha256(payload).digest()


# ---------------------------------------------------------------------------
#  Chain-hash computation  (extracted from views.py for reuse)
# ---------------------------------------------------------------------------

def compute_chain_hash(
    prev_chain_hash: str,
    payload_hash: str,
    algorithm: str,
    signature_b64: str,
    timestamp_iso: str,
) -> str:
    """
    Deterministic chain-hash for one ``DocumentVersion`` block.

    Pre-image layout (pipe-delimited):
        ``prev_chain_hash | payload_hash | algorithm | signature_b64 | timestamp_iso``

    Returns the SHA-256 hex digest.
    """
    material = "|".join(
        [prev_chain_hash or "", payload_hash, algorithm, signature_b64, timestamp_iso]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
