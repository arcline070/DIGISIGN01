"""
Full chain-traversal auditor for the immutable document version ledger.

Vulnerability #4 — Complete Chain Traversal (Deep Audit)
---------------------------------------------------------
``verify_entire_chain`` walks every ``DocumentVersion`` for a given
``DocumentRecord`` sequentially from H_0 to H_n, recomputing the SHA-256
chain hash at each step.  Any mismatch — in the ``prev_chain_hash`` link
**or** the recomputed ``chain_hash`` — is flagged with the exact version
number, expected vs. stored values, and a human-readable reason.

Returns
~~~~~~~
A ``ChainAuditReport`` dataclass that is truthy when the chain is valid
and exposes a ``.to_dict()`` serialization for API responses.
"""
from __future__ import annotations

import dataclasses
import logging
from typing import List, Optional

from django.conf import settings

from api.models import DocumentRecord, DocumentVersion
from api.utils.crypto import compute_chain_hash

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
#  Data structures
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class VersionAuditEntry:
    """Audit result for a single version in the chain."""

    version_no: int
    stored_prev_chain_hash: str
    expected_prev_chain_hash: str
    stored_chain_hash: str
    recomputed_chain_hash: str
    valid: bool
    reason: str = ""

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        return d


@dataclasses.dataclass
class ChainAuditReport:
    """Complete audit report for one document's hash chain."""

    document_record_id: int
    doc_id: str
    total_versions: int
    verified_count: int
    is_valid: bool
    broken_at_version: Optional[int]
    entries: List[VersionAuditEntry]
    genesis_hash_used: str

    def __bool__(self) -> bool:          # noqa: D105
        return self.is_valid

    def to_dict(self) -> dict:
        return {
            "document_record_id": self.document_record_id,
            "doc_id": self.doc_id,
            "total_versions": self.total_versions,
            "verified_count": self.verified_count,
            "is_valid": self.is_valid,
            "broken_at_version": self.broken_at_version,
            "genesis_hash_used": self.genesis_hash_used,
            "entries": [e.to_dict() for e in self.entries],
        }


# ---------------------------------------------------------------------------
#  Public API
# ---------------------------------------------------------------------------

def verify_entire_chain(document_record_id: int) -> ChainAuditReport:
    """
    Traverse every ``DocumentVersion`` for the given ``DocumentRecord.pk``
    from version 1 → N and mathematically verify the hash chain.

    Steps for each version *v*:

    1. **Link check** — ``v.prev_chain_hash`` must equal:
       - ``settings.HASH_CHAIN_GENESIS`` if *v* is the first version, or
       - ``versions[v-1].chain_hash`` otherwise.
    2. **Recomputation check** — Recompute the chain hash from the block
       fields (prev_chain_hash, payload_hash, algorithm, signature_b64,
       created_at) and compare against the stored ``v.chain_hash``.

    Parameters
    ----------
    document_record_id : int
        Primary key of the ``DocumentRecord`` to audit.

    Returns
    -------
    ChainAuditReport
        ``.is_valid`` is ``True`` only when every link passes both checks.
    """
    genesis_hash: str = settings.HASH_CHAIN_GENESIS

    try:
        record = DocumentRecord.objects.get(pk=document_record_id)
    except DocumentRecord.DoesNotExist:
        return ChainAuditReport(
            document_record_id=document_record_id,
            doc_id="",
            total_versions=0,
            verified_count=0,
            is_valid=False,
            broken_at_version=None,
            entries=[],
            genesis_hash_used=genesis_hash,
        )

    versions: list[DocumentVersion] = list(
        record.versions.order_by("version_no")
    )

    entries: list[VersionAuditEntry] = []
    broken_at: Optional[int] = None
    chain_valid = True
    prev_hash: str = genesis_hash  # H_0 seed

    for idx, version in enumerate(versions):
        # ── 1. Link check ──────────────────────────────────────────
        link_ok = (version.prev_chain_hash or "") == prev_hash
        reason_parts: list[str] = []
        if not link_ok:
            reason_parts.append(
                f"prev_chain_hash mismatch: stored={version.prev_chain_hash!r}, "
                f"expected={prev_hash!r}"
            )

        # ── 2. Recomputation check ─────────────────────────────────
        recomputed = compute_chain_hash(
            prev_chain_hash=version.prev_chain_hash or "",
            payload_hash=version.payload_hash,
            algorithm=version.algorithm,
            signature_b64=version.signature_b64,
            timestamp_iso=version.created_at.isoformat(),
        )
        hash_ok = recomputed == version.chain_hash
        if not hash_ok:
            reason_parts.append(
                f"chain_hash mismatch: stored={version.chain_hash!r}, "
                f"recomputed={recomputed!r}"
            )

        step_valid = link_ok and hash_ok
        entry = VersionAuditEntry(
            version_no=version.version_no,
            stored_prev_chain_hash=version.prev_chain_hash or "",
            expected_prev_chain_hash=prev_hash,
            stored_chain_hash=version.chain_hash,
            recomputed_chain_hash=recomputed,
            valid=step_valid,
            reason="; ".join(reason_parts) if reason_parts else "OK",
        )
        entries.append(entry)

        if not step_valid and chain_valid:
            chain_valid = False
            broken_at = version.version_no
            logger.warning(
                "Chain integrity violation at doc=%s version=%d: %s",
                record.doc_id,
                version.version_no,
                entry.reason,
            )

        # Advance the running hash for the next iteration.
        # Use the *stored* chain_hash (not recomputed) so that subsequent
        # versions are evaluated against what was actually persisted — this
        # allows us to pinpoint the *first* divergence precisely.
        prev_hash = version.chain_hash

    return ChainAuditReport(
        document_record_id=document_record_id,
        doc_id=record.doc_id,
        total_versions=len(versions),
        verified_count=len(entries),
        is_valid=chain_valid,
        broken_at_version=broken_at,
        entries=entries,
        genesis_hash_used=genesis_hash,
    )
