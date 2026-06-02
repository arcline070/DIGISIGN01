"""
Service layer for immutable document version creation with hash chaining.

Vulnerability #1 — Race Condition Prevention (the "Forking" problem)
---------------------------------------------------------------------
``create_document_version`` wraps the entire read-of-H_{n-1} → compute-H_n →
INSERT sequence inside ``transaction.atomic()`` **and** locks the previous
version row with ``select_for_update()`` so a concurrent request on the same
document is serialized rather than branching the chain.

Vulnerability #3 — Secure Genesis Block (H_0)
----------------------------------------------
When a ``DocumentRecord`` has zero versions the genesis constant from
``settings.HASH_CHAIN_GENESIS`` is used as ``prev_chain_hash``.  That value
is loaded from the ``HASH_CHAIN_GENESIS`` environment variable and validated
at startup (see ``settings.py`` additions).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django.conf import settings
from django.db import IntegrityError, transaction

from api.models import DocumentRecord, DocumentVersion
from api.utils.crypto import compute_chain_hash, sha256_hex

logger = logging.getLogger(__name__)


class ChainForkError(Exception):
    """Raised when an integrity violation is detected during chain append."""


def create_document_version(
    *,
    user,
    doc_id: str,
    payload_hash: str,
    algorithm: str,
    certificate_pem: str,
    signature_b64: str,
    metadata: dict,
) -> tuple["DocumentRecord", "DocumentVersion"]:
    """
    Atomically append a new ``DocumentVersion`` to the hash chain for
    *doc_id*, returning ``(record, version)``.

    Concurrency guarantees
    ~~~~~~~~~~~~~~~~~~~~~~
    1. ``transaction.atomic()`` wraps the full critical section.
    2. The *latest* existing version row (if any) is locked via
       ``select_for_update()`` before its ``chain_hash`` is read.
       Any concurrent caller issuing the same query will **block** on
       the row lock until the current transaction commits or rolls back,
       preventing two callers from reading the same H_{n-1}.
    3. The ``unique_together = ("record", "version_no")`` constraint on the
       model provides a final DB-level safety net — even if a lock were
       somehow bypassed, one of the two INSERTs would fail with
       ``IntegrityError``.

    Genesis block
    ~~~~~~~~~~~~~
    When no previous version exists the genesis hash configured in
    ``settings.HASH_CHAIN_GENESIS`` is used as the ``prev_chain_hash``.
    """
    genesis_hash: str = settings.HASH_CHAIN_GENESIS  # Vulnerability #3

    # Parse certificate fingerprint outside the atomic section to avoid
    # holding the row lock longer than necessary.
    cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    try:
        with transaction.atomic():
            # ── Step 1: Get or create the logical document stream ──────
            record, _ = DocumentRecord.objects.select_for_update().get_or_create(
                doc_id=doc_id,
                defaults={"owner": user},
            )
            if record.owner_id != user.id:
                raise ValueError("Document ID belongs to another user.")

            # ── Step 2: Lock the latest version row (pessimistic lock) ─
            last_version = (
                record.versions
                .select_for_update()          # ← ROW LOCK
                .order_by("-version_no")
                .first()
            )

            version_no = 1 if last_version is None else (last_version.version_no + 1)

            # ── Step 3: Genesis fallback or chain from predecessor ─────
            if last_version is None:
                prev_chain_hash = genesis_hash        # H_0
            else:
                prev_chain_hash = last_version.chain_hash   # H_{n-1}

            # ── Step 4: Compute H_n ───────────────────────────────────
            created_at = datetime.now(timezone.utc)
            timestamp_iso = created_at.isoformat()

            chain_hash = compute_chain_hash(
                prev_chain_hash=prev_chain_hash,
                payload_hash=payload_hash,
                algorithm=algorithm,
                signature_b64=signature_b64,
                timestamp_iso=timestamp_iso,
            )

            # ── Step 5: Atomic INSERT ─────────────────────────────────
            version = DocumentVersion.objects.create(
                record=record,
                version_no=version_no,
                created_at=created_at,
                signer=user,
                algorithm=algorithm,
                certificate_fingerprint=fingerprint,
                payload_hash=payload_hash,
                prev_chain_hash=prev_chain_hash,
                chain_hash=chain_hash,
                signature_b64=signature_b64,
                metadata_json=metadata,
            )

    except IntegrityError as exc:
        # The unique_together constraint caught a duplicate version_no —
        # this means another transaction committed between our read and
        # write despite the row lock (should never happen on PostgreSQL
        # with proper isolation, but defend in depth).
        logger.error(
            "Chain fork prevented by DB constraint for doc=%s version=%s: %s",
            doc_id,
            version_no,
            exc,
        )
        raise ChainForkError(
            f"Concurrent chain fork detected for document '{doc_id}'. "
            "Retry the operation."
        ) from exc

    return record, version
