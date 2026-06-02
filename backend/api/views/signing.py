"""Document signing views: sign, sign_document, add_document_version, my_document_ids."""
from __future__ import annotations

import base64
import json
import uuid

from django.http import HttpResponse
from rest_framework import status
from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from ..crypto_utils import mock_timestamp_token, sha256_hex, sign_data_with_algorithm
from ..key_utils import decrypt_private_key, ensure_user_profile
from ..models import AuditLog, DocumentRecord, SignatureLog, SignedDocumentArtifact

from ._helpers import (
    _canonical_json_text_from_bytes,
    _extract_input_bytes,
    _normalize_text_for_diff,
    _request_ip,
    _upsert_document_chain,
)
from ..crypto_utils import extract_pub_from_cert
from datetime import datetime, timezone


def _resolve_signing_document_id(request, *, require_existing: bool = False) -> str:
    document_id = str(request.data.get("document_id", "")).strip()
    if require_existing and not document_id:
        raise ValueError("document_id is required.")
    return document_id or str(uuid.uuid4())


def _build_signed_package_payload(
    *,
    data_bytes: bytes,
    original_filename: str | None,
    user,
    document_id: str,
    algorithm: str,
):
    user_profile = ensure_user_profile(user)
    digest_hex = sha256_hex(data_bytes)
    private_key_pem = decrypt_private_key(user_profile.private_key)
    certificate_pem = (user_profile.certificate or "").strip() or (
        user_profile.certificate_pem or ""
    ).strip()
    if not certificate_pem:
        raise ValueError("User certificate is missing.")

    document_b64 = base64.b64encode(data_bytes).decode("ascii")
    now = datetime.now(timezone.utc)
    structured_snapshot = _canonical_json_text_from_bytes(data_bytes)
    normalized_text_for_diff, diff_kind = _normalize_text_for_diff(data_bytes, original_filename)

    sig_raw = sign_data_with_algorithm(data_bytes, private_key_pem, algorithm)
    sig_b64 = base64.b64encode(sig_raw).decode("ascii")
    public_key_pem = extract_pub_from_cert(certificate_pem)

    signed_package: dict[str, str] = {
        "document": document_b64,
        "signed_data": document_b64,
        "original_data": document_b64,
        "signature": sig_b64,
        "certificate": certificate_pem,
        "public_key": public_key_pem,
        "signed_by": user.username,
        "timestamp": now.isoformat(),
        "algorithm": algorithm,
        "hash_algorithm": "SHA-256",
        "signature_algorithm": "RSA-PKCS1v15"
        if algorithm == "RSA-SHA256"
        else "ECDSA-SECP256R1",
        "document_id": document_id,
        "hash": digest_hex,
    }
    if original_filename:
        signed_package["original_filename"] = str(original_filename)
        signed_package["document_name"] = str(original_filename)
        if "." in str(original_filename):
            signed_package["document_type"] = str(original_filename).rsplit(".", 1)[-1].lower()
    if structured_snapshot is not None:
        signed_package["structured_snapshot"] = structured_snapshot

    record, version = _upsert_document_chain(
        user=user,
        doc_id=document_id,
        payload_hash=digest_hex,
        algorithm=algorithm,
        certificate_pem=certificate_pem,
        signature_b64=sig_b64,
        metadata={
            "timestamp": now.isoformat(),
            "signed_by": user.username,
            "original_filename": original_filename or "",
            "structured": structured_snapshot is not None,
            "structured_snapshot": structured_snapshot or "",
            "diff_kind": diff_kind,
            "original_text": normalized_text_for_diff or "",
        },
    )
    signed_package["version_no"] = str(version.version_no)
    signed_package["chain_hash"] = version.chain_hash
    signed_package["prev_chain_hash"] = version.prev_chain_hash

    SignedDocumentArtifact.objects.update_or_create(
        version=version,
        defaults={
            "original_filename": original_filename or "",
            "original_bytes": data_bytes,
            "signature_b64": sig_b64,
            "certificate_pem": certificate_pem,
            "algorithm": algorithm,
            "hash_hex": digest_hex,
            "signed_package_json": signed_package,
        },
    )

    return signed_package, digest_hex, sig_b64, public_key_pem


def _persist_signing_audit(request, *, user, data_for_log, digest_hex, sig_b64, public_key_pem):
    SignatureLog.objects.create(
        user=user,
        action=SignatureLog.Action.SIGN,
        status=SignatureLog.Status.SUCCESS,
        data_hash=digest_hex,
        ip_address=_request_ip(request),
        data=data_for_log,
        hash_hex=digest_hex,
        signature=sig_b64,
        public_key=public_key_pem,
    )
    AuditLog.objects.create(
        user=user,
        action=AuditLog.Action.SIGN,
        status=AuditLog.Status.SUCCESS,
        data_hash=digest_hex,
        ip_address=_request_ip(request),
    )


def _build_signed_document_response(signed_package: dict) -> HttpResponse:
    response = HttpResponse(
        json.dumps(signed_package, indent=2),
        content_type="application/json",
    )
    response["Content-Disposition"] = 'attachment; filename="signed.json"'
    return response


def _sign_document_for_response(request, *, require_existing: bool = False):
    data_bytes, data_for_log, original_filename = _extract_input_bytes(request)
    user = request.user
    algorithm = ensure_user_profile(user).signature_algorithm or "RSA-SHA256"
    document_id = _resolve_signing_document_id(request, require_existing=require_existing)
    signed_package, digest_hex, sig_b64, public_key_pem = _build_signed_package_payload(
        data_bytes=data_bytes,
        original_filename=original_filename,
        user=user,
        document_id=document_id,
        algorithm=algorithm,
    )
    _persist_signing_audit(
        request,
        user=user,
        data_for_log=data_for_log,
        digest_hex=digest_hex,
        sig_b64=sig_b64,
        public_key_pem=public_key_pem,
    )
    return _build_signed_document_response(signed_package)


# ---------------------------------------------------------------------------
#  SIGN DOCUMENT → Downloadable signed JSON package
#  Verification must fail on ANY modification to ensure integrity and
#  authenticity.
# ---------------------------------------------------------------------------


@api_view(["POST"])
@parser_classes([JSONParser, MultiPartParser, FormParser])
@permission_classes([IsAuthenticated])
def sign_document(request):
    """
    Sign a file or text and return a self-contained signed JSON package.

    The package contains:
      - document (base64-encoded raw bytes that were signed)
      - signature (base64-encoded RSA-SHA256 signature)
      - certificate (PEM-encoded self-signed X.509 certificate)
      - signed_by (username)
      - timestamp
      - algorithm identifier

    Verification must fail on ANY modification to ensure integrity and
    authenticity.
    """
    try:
        return _sign_document_for_response(request)
    except Exception as e:
        return Response(
            {
                "status": "failed",
                "message": str(e),
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@parser_classes([JSONParser, MultiPartParser, FormParser])
@permission_classes([IsAuthenticated])
def add_document_version(request):
    """Append a new signed version to an existing document chain."""
    try:
        return _sign_document_for_response(request, require_existing=True)
    except Exception as e:
        return Response(
            {
                "status": "failed",
                "message": str(e),
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def my_document_ids(request):
    document_ids = list(
        DocumentRecord.objects.filter(owner=request.user)
        .order_by("doc_id")
        .values_list("doc_id", flat=True)
    )
    return Response({"document_ids": document_ids})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def my_document_ids_with_metadata(request):
    """Return document IDs with metadata (creation date, owner)."""
    records = DocumentRecord.objects.filter(owner=request.user).order_by("created_at")
    documents = []
    for record in records:
        first_version = record.versions.order_by("version_no").first()
        filename = ""
        if first_version:
            filename = first_version.metadata_json.get("original_filename", "")
            
        documents.append({
            "id": record.doc_id,
            "created_at": record.created_at.isoformat(),
            "owner": record.owner.username,
            "filename": filename,
        })
    return Response({"documents": documents})


# ---------------------------------------------------------------------------
#  SIGN endpoint — supports both file and text input
# ---------------------------------------------------------------------------

@api_view(["POST"])
@parser_classes([JSONParser, MultiPartParser, FormParser])
@permission_classes([IsAuthenticated])
def sign(request):
    """Sign normalized payload with user's private key; never returns private key."""
    try:
        # Extract input — handles BOTH file and text (NO .decode() on file!)
        data_bytes, data_for_log, _ = _extract_input_bytes(request)

        user = request.user
        user_profile = ensure_user_profile(user)
        digest_hex = sha256_hex(data_bytes)

        # Decrypt private key only in memory — NEVER return it
        private_key_pem = decrypt_private_key(user_profile.private_key)
        algorithm = user_profile.signature_algorithm or "RSA-SHA256"
        sig_raw = sign_data_with_algorithm(data_bytes, private_key_pem, algorithm)
        sig_b64 = base64.b64encode(sig_raw).decode("ascii")

        # Get public key for response
        public_key_pem = user_profile.public_key

        log = SignatureLog.objects.create(
            user=user,
            action=SignatureLog.Action.SIGN,
            status=SignatureLog.Status.SUCCESS,
            data_hash=digest_hex,
            ip_address=_request_ip(request),
            data=data_for_log,
            hash_hex=digest_hex,
            signature=sig_b64,
            public_key=public_key_pem,
        )
        AuditLog.objects.create(
            user=user,
            action=AuditLog.Action.SIGN,
            status=AuditLog.Status.SUCCESS,
            data_hash=digest_hex,
            ip_address=_request_ip(request),
        )

        return Response(
            {
                "signature": sig_b64,
                "public_key": public_key_pem,
                "username": user.username,
                "hash": digest_hex,
                "algorithm": algorithm,
                "timestamp": log.timestamp,
                "timestamp_token": mock_timestamp_token(),
            }
        )

    except Exception as e:
        return Response(
            {
                "status": "failed",
                "message": str(e),
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
