from __future__ import annotations

import base64
import csv
import hmac
import io
import json
import zipfile
import time
import uuid
from statistics import mean
from datetime import datetime, timezone
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from openpyxl import Workbook
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from .crypto_utils import (
    create_key_pair,
    extract_pub_from_cert,
    mock_timestamp_token,
    normalize_external_public_key_pem,
    sha256_hex,
    sign_data,
    sign_data_with_algorithm,
    verify_signature,
    verify_signature_with_algorithm,
)
from .key_utils import decrypt_private_key, ensure_user_profile
from .models import (
    AuditLog,
    DocumentRecord,
    DocumentVersion,
    SignatureLog,
    SignedDocumentArtifact,
)
from .serializers import (
    AuditLogSerializer,
    ExportRequestSerializer,
    LoginSerializer,
    RegisterSerializer,
)
from .utils.diff_engine import detect_changes


def _export_payload(log: SignatureLog) -> dict:
    return {
        "data": log.data,
        "username": log.user.username,
        "timestamp": log.timestamp.isoformat(),
        "hash": log.hash_hex,
        "signature": log.signature,
        "public_key": log.public_key,
    }


def _request_ip(request) -> str | None:
    forwarded = (request.META.get("HTTP_X_FORWARDED_FOR") or "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    return (request.META.get("REMOTE_ADDR") or "").strip() or None


def _normalize_json_bytes(data_bytes: bytes) -> bytes:
    """Normalize JSON to canonical form for deterministic signing/verification."""
    try:
        obj = json.loads(data_bytes.decode("utf-8"))
        return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return data_bytes


def _extract_input_bytes(request):
    """
    Extract data_bytes from request handling BOTH text and file input.

    For files: reads raw bytes directly (NO decode).
    For text/JSON: encodes to UTF-8 bytes.

    Returns (data_bytes, data_for_log, original_filename).
    """
    file_obj = request.FILES.get("file")
    original_filename = None

    if file_obj:
        # CRITICAL: Read raw bytes from file — DO NOT decode
        data_bytes = file_obj.read()
        original_filename = file_obj.name
        data_for_log = f"[FILE:{file_obj.name};BYTES:{len(data_bytes)}]"
        # Normalize JSON files for deterministic signing
        if file_obj.name.endswith(".json"):
            data_bytes = _normalize_json_bytes(data_bytes)
    else:
        text_raw = request.data.get("data", "")
        if isinstance(text_raw, (dict, list)):
            text_data = json.dumps(
                text_raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
        else:
            text_data = str(text_raw)
        data_bytes = text_data.encode("utf-8")
        data_for_log = text_data

    return data_bytes, data_for_log, original_filename


def _canonical_json_text_from_bytes(data_bytes: bytes) -> str | None:
    try:
        obj = json.loads(data_bytes.decode("utf-8"))
        if isinstance(obj, (dict, list)):
            return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return None
    except Exception:
        return None


def _normalize_text_for_diff(data_bytes: bytes, filename: str | None) -> tuple[str | None, str]:
    """
    Normalize UTF-8 text for diff. Supports text, JSON, CSV.
    Returns (normalized_text_or_none, kind)
    kind in {"json","csv","text","binary"}
    """
    name = (filename or "").lower()
    try:
        text = data_bytes.decode("utf-8")
    except Exception:
        return None, "binary"

    if name.endswith(".json"):
        try:
            obj = json.loads(text)
            return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False), "json"
        except Exception:
            return text, "text"

    if name.endswith(".csv"):
        return text, "csv"

    # Default: treat as generic text
    return text, "text"


def _flatten_json_for_diff(value, prefix: str = "$") -> dict[str, object]:
    out: dict[str, object] = {}
    if isinstance(value, dict):
        for k, v in value.items():
            out.update(_flatten_json_for_diff(v, f"{prefix}.{k}"))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out.update(_flatten_json_for_diff(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = value
    return out


def _json_localization_diff(expected_json_text: str, actual_json_text: str) -> dict:
    expected_obj = json.loads(expected_json_text)
    actual_obj = json.loads(actual_json_text)
    expected_map = _flatten_json_for_diff(expected_obj)
    actual_map = _flatten_json_for_diff(actual_obj)
    expected_keys = set(expected_map.keys())
    actual_keys = set(actual_map.keys())
    added = sorted(actual_keys - expected_keys)
    deleted = sorted(expected_keys - actual_keys)
    modified = sorted(
        k for k in (expected_keys & actual_keys) if expected_map[k] != actual_map[k]
    )
    return {
        "added_fields": added,
        "deleted_fields": deleted,
        "modified_fields": modified,
        "summary": {
            "added_count": len(added),
            "deleted_count": len(deleted),
            "modified_count": len(modified),
        },
    }


def _json_tamper_report(original_text: str, current_text: str) -> dict:
    original_obj = json.loads(original_text)
    current_obj = json.loads(current_text)
    original_map = _flatten_json_for_diff(original_obj)
    current_map = _flatten_json_for_diff(current_obj)
    original_keys = set(original_map.keys())
    current_keys = set(current_map.keys())

    added = [f"{k}: {current_map[k]}" for k in sorted(current_keys - original_keys)]
    deleted = [f"{k}: {original_map[k]}" for k in sorted(original_keys - current_keys)]
    modified = [
        {"from": f"{k}: {original_map[k]}", "to": f"{k}: {current_map[k]}"}
        for k in sorted(original_keys & current_keys)
        if original_map[k] != current_map[k]
    ]
    return {"added": added, "deleted": deleted, "modified": modified}


def _localize_tamper(
    original_bytes: bytes, current_bytes: bytes, filename: str | None
) -> tuple[dict | None, str | None]:
    """
    Localize tamper for text/json/csv only. Returns (report, message_if_unavailable).
    """
    name = (filename or "").lower()
    original_text, original_kind = _normalize_text_for_diff(original_bytes, name)
    current_text, current_kind = _normalize_text_for_diff(current_bytes, name)
    if original_text is None or current_text is None:
        return None, "Tamper localization supports only UTF-8 text/JSON/CSV."

    kind = "json" if original_kind == "json" or current_kind == "json" else (
        "csv" if original_kind == "csv" or current_kind == "csv" else "text"
    )

    if kind == "json":
        return _json_tamper_report(original_text, current_text), None

    # text/csv line-based diff
    report = detect_changes(original_text, current_text)
    return report, None


def _alg_spec_from_package(signature_algorithm: str) -> tuple[str, str]:
    """
    Map package algorithm labels to internal profile algorithm + key type.
    Returns (internal_algorithm, key_type) where key_type in {"rsa","ecdsa"}.
    """
    alg = (signature_algorithm or "").strip()
    if alg == "RSA-PKCS1v15":
        return "RSA-SHA256", "rsa"
    if alg == "ECDSA-SECP256R1":
        return "ECDSA-P256-SHA256", "ecdsa"
    raise ValueError("Unsupported signature_algorithm.")


def _compute_chain_hash(
    prev_chain_hash: str,
    payload_hash: str,
    algorithm: str,
    signature_b64: str,
    timestamp_iso: str,
) -> str:
    material = "|".join(
        [prev_chain_hash or "", payload_hash, algorithm, signature_b64, timestamp_iso]
    )
    return sha256(material.encode("utf-8")).hexdigest()


def _build_chain_verification(document_id: str | None) -> dict:
    """
    PHASE 3: Chronological Chain Verification

    Validates that no direct database modifications have occurred by:
    1. Fetching all DocumentVersion entries ordered by version_no
    2. For each version, verifying:
       - Its prev_chain_hash matches the previous version's chain_hash
       - The recomputed chain_hash matches the stored chain_hash
    3. Detecting any broken links indicating tampering

    Returns a dict with:
      - status: "valid" or "invalid"
      - verified_versions: count of versions checked
      - broken_at_version: version_no where chain broke, or None
    """
    chain_verification = {
        "status": "invalid",
        "verified_versions": 0,
        "broken_at_version": None,
    }

    if not document_id:
        return chain_verification

    rec = DocumentRecord.objects.filter(doc_id=document_id).first()
    if not rec:
        return chain_verification

    versions = list(rec.versions.order_by("version_no"))
    chain_verification["verified_versions"] = len(versions)

    prev_version = None
    for version in versions:
        # For the first version, expect "GENESIS" as prev_chain_hash anchor
        expected_prev = "GENESIS" if prev_version is None else prev_version.chain_hash
        if (version.prev_chain_hash or "") != expected_prev:
            chain_verification["status"] = "invalid"
            chain_verification["broken_at_version"] = version.version_no
            return chain_verification

        # Recompute the chain_hash and verify it matches the stored value
        expected_chain_hash = _compute_chain_hash(
            prev_chain_hash=version.prev_chain_hash or "",
            payload_hash=version.payload_hash,
            algorithm=version.algorithm,
            signature_b64=version.signature_b64,
            timestamp_iso=version.created_at.isoformat(),
        )
        if expected_chain_hash != version.chain_hash:
            chain_verification["status"] = "invalid"
            chain_verification["broken_at_version"] = version.version_no
            return chain_verification

        prev_version = version

    chain_verification["status"] = "valid"
    return chain_verification


def _upsert_document_chain(
    *,
    user,
    doc_id: str,
    payload_hash: str,
    algorithm: str,
    certificate_pem: str,
    signature_b64: str,
    metadata: dict,
) -> tuple[DocumentRecord, DocumentVersion]:
    """
    PHASE 1 & 2: Append-Only Storage with Hash Chaining

    For each signed document:
    1. Lookup or Create Record: Get or create DocumentRecord by doc_id
    2. Determine Versioning: Find last version
       - If none exists: Version 1, prev_chain_hash = "GENESIS"
       - If exists: Increment version number, prev_chain_hash = last version's chain_hash
    3. Compute Block Link: Calculate chain_hash using current block data + previous hash
    4. Persistent Save: Create new DocumentVersion row (append-only, never update)
    """
    record, _ = DocumentRecord.objects.get_or_create(
        doc_id=doc_id,
        defaults={"owner": user},
    )
    if record.owner_id != user.id:
        # keep ownership stable; do not reassign implicitly
        raise ValueError("Document ID belongs to another user.")

    last_version = record.versions.order_by("-version_no").first()
    version_no = 1 if not last_version else (last_version.version_no + 1)
    
    # GENESIS chain anchor for first version, or chain_hash of previous version
    prev_chain_hash = "GENESIS" if not last_version else last_version.chain_hash
    
    created_at = datetime.now(timezone.utc)
    timestamp_iso = created_at.isoformat()
    chain_hash = _compute_chain_hash(
        prev_chain_hash, payload_hash, algorithm, signature_b64, timestamp_iso
    )
    cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

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
    return record, version


def _create_qr_token(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    secret = (settings.SECRET_KEY or "").encode("utf-8")
    sig = hmac.new(secret, body.encode("utf-8"), sha256).hexdigest()
    token_obj = {"payload": payload, "sig": sig}
    token_json = json.dumps(token_obj, separators=(",", ":"), ensure_ascii=False)
    return base64.urlsafe_b64encode(token_json.encode("utf-8")).decode("ascii")


def _build_verification_details(package: dict) -> dict:
    cert_pem = str(package.get("certificate") or "").strip()
    certificate_owner = "N/A"
    certificate_expiry = "N/A"

    if cert_pem:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
            owner_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            certificate_owner = owner_attrs[0].value if owner_attrs else "N/A"
            certificate_expiry = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            certificate_owner = "N/A"
            certificate_expiry = "N/A"

    return {
        "signature_status": "Verified / Authentic",
        "timestamp": str(package.get("timestamp") or "N/A"),
        "original_file_name": str(package.get("original_filename") or "verified_document.json"),
        "certificate_owner": certificate_owner,
        "certificate_expiry": certificate_expiry,
        "signed_by": str(package.get("signed_by") or "N/A"),
        "algorithm": str(package.get("signature_algorithm") or package.get("algorithm") or "N/A"),
    }


def _verify_qr_token(token: str) -> tuple[bool, dict | str]:
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        obj = json.loads(raw)
        payload = obj["payload"]
        sig = obj["sig"]
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        expected_sig = hmac.new(
            (settings.SECRET_KEY or "").encode("utf-8"),
            body.encode("utf-8"),
            sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return False, "Invalid QR signature"
        exp = payload.get("exp_unix")
        if exp is not None and int(time.time()) > int(exp):
            return False, "QR token expired"
        return True, payload
    except Exception:
        return False, "Invalid QR token"


def _verify_signed_package(package: dict, request) -> tuple[bool, dict]:
    """
    Verify signed package and return (ok, details/message payload).
    """
    document_b64 = package.get("original_data") or package.get("signed_data") or package.get("document")
    signature_b64 = package.get("signature")
    certificate_pem = package.get("certificate")
    public_key_pem = package.get("public_key")
    signed_by = package.get("signed_by")
    timestamp = package.get("timestamp")
    signature_algorithm = package.get("signature_algorithm")
    document_id = package.get("document_id")
    original_filename = package.get("original_filename")
    structured_snapshot = package.get("structured_snapshot")
    claimed_hash = package.get("hash")

    if (
        not document_b64
        or not signature_b64
        or not signature_algorithm
        or not (certificate_pem or public_key_pem)
        or not signed_by
        or not timestamp
    ):
        return False, {
            "status": "invalid",
            "message": "Signed package is missing required fields.",
        }
    try:
        algorithm, expected_key_type = _alg_spec_from_package(str(signature_algorithm))
    except Exception:
        return False, {"status": "invalid", "message": "Unsupported signature_algorithm."}

    try:
        data_bytes = base64.b64decode(document_b64, validate=True)
    except Exception:
        return False, {"status": "invalid", "message": "Invalid base64 in document field."}

    computed_hash = sha256_hex(data_bytes)
    if str(claimed_hash or "").strip() and str(claimed_hash).strip() != computed_hash:
        return False, {"status": "invalid", "message": "Hash mismatch."}

    cert = None
    if certificate_pem:
        try:
            cert = x509.load_pem_x509_certificate(str(certificate_pem).encode("utf-8"))
        except Exception:
            return False, {"status": "invalid", "message": "Invalid certificate."}

    if cert is not None:
        now_utc = datetime.utcnow()
        if cert.not_valid_before > now_utc or cert.not_valid_after < now_utc:
            return False, {"status": "invalid", "message": "Certificate expired or not yet valid."}

    certificate_owner = ""
    if cert is not None:
        owner_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        certificate_owner = owner_attrs[0].value if owner_attrs else ""
        if str(signed_by).strip() != str(certificate_owner).strip():
            return False, {"status": "invalid", "message": "Signed by does not match certificate owner."}

    try:
        signature_bytes = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False, {"status": "invalid", "message": "Invalid base64 in signature field."}

    try:
        if public_key_pem:
            verify_public_key = serialization.load_pem_public_key(
                str(public_key_pem).encode("utf-8")
            )
        elif cert is not None:
            verify_public_key = cert.public_key()
        else:
            return False, {"status": "invalid", "message": "No verification key available."}
    except Exception:
        return False, {"status": "invalid", "message": "Invalid public key."}

    # Strict algorithm/key type matching.
    if expected_key_type == "rsa" and not isinstance(verify_public_key, rsa.RSAPublicKey):
        return False, {"status": "invalid", "message": "Algorithm/key type mismatch."}
    if expected_key_type == "ecdsa" and not isinstance(
        verify_public_key, ec.EllipticCurvePublicKey
    ):
        return False, {"status": "invalid", "message": "Algorithm/key type mismatch."}

    try:
        if algorithm == "RSA-SHA256":
            verify_public_key.verify(
                signature_bytes,
                data_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        else:
            verify_public_key.verify(
                signature_bytes,
                data_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
    except Exception:
        return False, {
            "status": "invalid",
            "message": "Tampered or invalid signature. Verification must fail on ANY modification to ensure integrity and authenticity.",
            "certificate_owner": certificate_owner,
            "certificate_valid_until": cert.not_valid_after.date().isoformat() if cert is not None else "",
        }

    return True, {
        "status": "valid",
        "signed_by": signed_by,
        "timestamp": timestamp,
        "algorithm": algorithm,
        "signature_algorithm": signature_algorithm,
        "document_id": document_id or "",
        "hash": computed_hash,
        "original_filename": original_filename or "",
        "structured_snapshot": structured_snapshot if isinstance(structured_snapshot, str) else "",
        "certificate_owner": certificate_owner,
        "certificate_valid_until": cert.not_valid_after.date().isoformat() if cert is not None else "",
        "document_bytes": data_bytes,
        "certificate_pem": certificate_pem,
    }


def _manifest_seal(payload: dict) -> str:
    """Tamper-evident HMAC seal for verification manifest."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    secret = (settings.SECRET_KEY or "").encode("utf-8")
    return hmac.new(secret, canonical.encode("utf-8"), sha256).hexdigest()


def _algorithm_from_public_key_pem(public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA-SHA256"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA-P256-SHA256"
    raise ValueError("Unsupported public key type")


def _build_receipt_pdf(receipt: dict) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 60
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Digital Signature Verification Receipt")
    y -= 30
    c.setFont("Helvetica", 10)
    for key, value in receipt.items():
        line = f"{key}: {value}"
        c.drawString(50, y, line[:140])
        y -= 16
        if y < 60:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 50
    c.save()
    return buffer.getvalue()


def _watermark_pdf_bytes(pdf_bytes: bytes, watermark_lines: list[str]) -> bytes:
    from pypdf import PdfReader, PdfWriter
    from reportlab.lib.colors import Color
    from reportlab.pdfgen import canvas

    src_reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()

    for page in src_reader.pages:
        page_width = float(page.mediabox.width)
        page_height = float(page.mediabox.height)

        overlay_buffer = io.BytesIO()
        c = canvas.Canvas(overlay_buffer, pagesize=(page_width, page_height))
        c.saveState()
        c.translate(page_width / 2, page_height / 2)
        c.rotate(35)
        c.setFillColor(Color(0.5, 0.5, 0.5, alpha=0.18))
        c.setFont("Helvetica-Bold", 18)
        y = 40
        for line in watermark_lines:
            c.drawCentredString(0, y, str(line)[:120])
            y -= 22
        c.restoreState()
        c.save()
        overlay_buffer.seek(0)
        overlay_page = PdfReader(overlay_buffer).pages[0]

        page.merge_page(overlay_page)
        writer.add_page(page)

    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def _benchmark_algorithm(algorithm: str, payload: bytes, runs: int) -> dict:
    keygen_times: list[float] = []
    sign_times: list[float] = []
    verify_times: list[float] = []

    for _ in range(runs):
        t0 = time.perf_counter()
        private_pem, public_pem = create_key_pair(algorithm)  # type: ignore[arg-type]
        keygen_times.append((time.perf_counter() - t0) * 1000.0)

        t1 = time.perf_counter()
        sig_raw = sign_data_with_algorithm(payload, private_pem, algorithm)  # type: ignore[arg-type]
        sign_times.append((time.perf_counter() - t1) * 1000.0)

        sig_b64 = base64.b64encode(sig_raw).decode("ascii")
        t2 = time.perf_counter()
        ok = verify_signature_with_algorithm(public_pem, sig_b64, payload, algorithm)  # type: ignore[arg-type]
        verify_times.append((time.perf_counter() - t2) * 1000.0)
        if not ok:
            raise ValueError(f"Benchmark verify failed for {algorithm}")

    return {
        "algorithm": algorithm,
        "runs": runs,
        "payload_size_bytes": len(payload),
        "keygen_ms_avg": round(mean(keygen_times), 4),
        "sign_ms_avg": round(mean(sign_times), 4),
        "verify_ms_avg": round(mean(verify_times), 4),
        "keygen_ms_min": round(min(keygen_times), 4),
        "sign_ms_min": round(min(sign_times), 4),
        "verify_ms_min": round(min(verify_times), 4),
    }


@api_view(["POST"])
@permission_classes([AllowAny])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    username = serializer.validated_data["username"].strip()
    password = serializer.validated_data["password"]
    signature_algorithm = serializer.validated_data.get("signature_algorithm") or "RSA-SHA256"
    if not username:
        return Response(
            {"detail": "Username is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    User = get_user_model()
    if User.objects.filter(username__iexact=username).exists():
        return Response(
            {"detail": "That username is already taken."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    user = User.objects.create_user(username=username, password=password)
    profile = ensure_user_profile(user, preferred_algorithm=signature_algorithm)
    token, _ = Token.objects.get_or_create(user=user)
    return Response(
        {
            "token": token.key,
            "username": user.username,
            "role": profile.role,
            "signature_algorithm": profile.signature_algorithm,
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    username = serializer.validated_data["username"].strip()
    password = serializer.validated_data["password"]
    user = authenticate(request, username=username, password=password)
    if user is None:
        return Response(
            {"detail": "Invalid username or password."},
            status=status.HTTP_401_UNAUTHORIZED,
        )
    profile = ensure_user_profile(user)
    token, _ = Token.objects.get_or_create(user=user)
    return Response(
        {
            "token": token.key,
            "username": user.username,
            "role": profile.role,
            "signature_algorithm": profile.signature_algorithm,
        }
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    Token.objects.filter(user=request.user).delete()
    return Response({"detail": "Logged out."})


# ---------------------------------------------------------------------------
#  SIGN DOCUMENT → Downloadable signed JSON package
#  Verification must fail on ANY modification to ensure integrity and
#  authenticity.
# ---------------------------------------------------------------------------


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
    documents = [
        {
            "id": record.doc_id,
            "created_at": record.created_at.isoformat(),
            "owner": record.owner.username,
        }
        for record in records
    ]
    return Response({"documents": documents})


# ---------------------------------------------------------------------------
#  VERIFY DOCUMENT → Accept uploaded signed JSON package
#  Verification must fail on ANY modification to ensure integrity and
#  authenticity.
# ---------------------------------------------------------------------------

@api_view(["POST"])
@parser_classes([MultiPartParser, FormParser])
@permission_classes([AllowAny])
def verify_document(request):
    """
    Verify a self-contained signed JSON package and validate the hash chain.

    PHASE 3: Chronological Chain Verification
    ─────────────────────────────────────────
    After cryptographic signature validation, this endpoint performs full-history
    verification against the database to guarantee no direct modifications have
    occurred in PostgreSQL:

    1. Fetch Sequence: Query all DocumentVersion entries ordered by version_no
    2. Sequential Validation Loop: For each version, verify:
       - v.prev_chain_hash matches the chain_hash of the previous version
       - The recomputed chain_hash matches the stored chain_hash
    3. Broken Link Detection: Flag any mismatch indicating database tampering

    Accepts the signed JSON package, extracts document, signature and
    certificate, then verifies the RSA-SHA256 signature.

    Verification must fail on ANY modification to ensure integrity and
    authenticity.
    """
    try:
        signed_package_file = request.FILES.get("file")

        if not signed_package_file:
            return Response(
                {
                    "status": "invalid",
                    "message": "No signed package file uploaded.",
                    "chain_verification": {
                        "status": "invalid",
                        "verified_versions": 0,
                        "broken_at_version": None,
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            raw = signed_package_file.read()
            package = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return Response(
                {
                    "status": "invalid",
                    "message": "File is not valid JSON.",
                    "chain_verification": {
                        "status": "invalid",
                        "verified_versions": 0,
                        "broken_at_version": None,
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        ok, details = _verify_signed_package(package, request)
        computed_hash = details.get("hash", "")
        doc_id = str(package.get("document_id") or "").strip()

        # Record audit log
        if request.user.is_authenticated:
            AuditLog.objects.create(
                user=request.user,
                action=AuditLog.Action.VERIFY,
                status=AuditLog.Status.SUCCESS if ok else AuditLog.Status.FAILED,
                data_hash=computed_hash,
                ip_address=_request_ip(request),
                failure_reason="" if ok else details.get("message", "Verification failed"),
            )

        # PHASE 3: Build chain verification.
        # Important: for uploaded packages we should validate the chain link for the specific uploaded version,
        # not only the DB baseline. This makes the UI properly detect “chain breaks” even when the uploaded
        # JSON was tampered or comes from a different chain state.
        chain_verification = _build_chain_verification(doc_id)

        package_version_no_raw = str(package.get("version_no") or "").strip()
        uploaded_prev = str(package.get("prev_chain_hash") or "").strip()
        uploaded_chain = str(package.get("chain_hash") or "").strip()

        if ok and doc_id and package_version_no_raw.isdigit() and uploaded_chain:
            v_no = int(package_version_no_raw)

            # Locate the corresponding DB version so we can recompute the expected chain hash for that version
            # using its stored immutable fields (payload_hash, algorithm, signature_b64, created_at).
            # Then we verify uploaded prev_chain_hash/chain_hash match expectations.
            rec = DocumentRecord.objects.filter(doc_id=doc_id).first()
            if rec:
                versions = list(rec.versions.order_by("version_no"))

                if 1 <= v_no <= len(versions):
                    idx = v_no - 1
                    if idx < len(versions):
                        db_version = versions[idx]
                        expected_prev = "GENESIS" if v_no == 1 else versions[idx - 1].chain_hash

                        # Expected chain_hash based on DB immutable fields.
                        expected_chain_hash = _compute_chain_hash(
                            prev_chain_hash=expected_prev,
                            payload_hash=db_version.payload_hash,
                            algorithm=db_version.algorithm,
                            signature_b64=db_version.signature_b64,
                            timestamp_iso=db_version.created_at.isoformat(),
                        )

                        # If the uploaded package’s chain linkage is inconsistent, mark chain invalid.
                        if (uploaded_prev or "") != expected_prev or uploaded_chain != expected_chain_hash:
                            chain_verification["status"] = "invalid"
                            chain_verification["broken_at_version"] = v_no


        if ok:
            # Signature verification passed → return valid response with chain status
            payload_data = package.get("data")
            if payload_data is None:
                payload_data = {}
            verification_details = _build_verification_details(package)
            return Response(
                {
                    "status": "valid",
                    "message": "Document Integrity Verified",
                    "algorithm_used": details.get("signature_algorithm", ""),
                    "verification_details": verification_details,
                    "original_data": json.dumps(payload_data),
                    "chain_verification": chain_verification,
                }
            )

        # Signature verification failed → Attempt automatic tamper localization
        version_no_raw = str(package.get("version_no") or "").strip()

        if not doc_id:
            return Response(
                {
                    "status": "invalid",
                    "message": details.get("message", "Invalid signature"),
                    "chain_verification": chain_verification,
                }
            )

        rec = DocumentRecord.objects.filter(doc_id=doc_id).first()
        if not rec:
            return Response(
                {
                    "status": "invalid",
                    "message": details.get("message", "Invalid signature"),
                    "note": "No trusted backend baseline found for automatic localization.",
                    "chain_verification": chain_verification,
                }
            )

        # Locate the specific version
        if version_no_raw and version_no_raw.isdigit():
            version = rec.versions.filter(version_no=int(version_no_raw)).first()
        else:
            version = rec.versions.order_by("-version_no").first()

        if not version or not hasattr(version, "artifact"):
            return Response(
                {
                    "status": "invalid",
                    "message": details.get("message", "Invalid signature"),
                    "note": "No trusted artifact found for automatic localization.",
                    "chain_verification": chain_verification,
                }
            )

        # Compare uploaded data against trusted backend-stored original bytes
        artifact = version.artifact
        trusted_bytes = bytes(artifact.original_bytes)
        uploaded_b64 = (
            str(package.get("original_data") or "").strip()
            or str(package.get("signed_data") or "").strip()
            or str(package.get("document") or "").strip()
        )
        try:
            uploaded_bytes = base64.b64decode(uploaded_b64, validate=True) if uploaded_b64 else b""
        except Exception:
            uploaded_bytes = b""

        filename_for_diff = str(package.get("document_name") or artifact.original_filename or "")
        tamper_report, err_msg = _localize_tamper(trusted_bytes, uploaded_bytes, filename_for_diff)

        if tamper_report is None:
            tamper_report = {"added": [], "deleted": [], "modified": []}
            note = err_msg or "Signature mismatch detected."
        else:
            note = ""

        return Response(
            {
                "status": "tampered",
                "message": "Document modified",
                "tamper_report": tamper_report,
                "note": note,
                "algorithm_used": package.get("signature_algorithm", ""),
                "chain_verification": chain_verification,
            }
        )

    except Exception as e:
        return Response(
            {
                "status": "failed",
                "message": str(e),
                "chain_verification": {
                    "status": "invalid",
                    "verified_versions": 0,
                    "broken_at_version": None,
                },
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@parser_classes([MultiPartParser, FormParser])
@permission_classes([AllowAny])
def verify_stored_document(request):
    """
    Verify using backend-stored signed artifact.

    Input:
      - current_file (required)
      - document_id (required)
      - version_no (optional; latest if omitted)
    """
    try:
        current_file = request.FILES.get("current_file")
        document_id = str(request.data.get("document_id", "")).strip()
        version_no_raw = str(request.data.get("version_no", "")).strip()
        chain_verification = _build_chain_verification(document_id)

        if not current_file:
            return Response(
                {
                    "status": "invalid",
                    "message": "No current file uploaded.",
                    "chain_verification": chain_verification,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not document_id:
            return Response(
                {
                    "status": "invalid",
                    "message": "document_id is required.",
                    "chain_verification": chain_verification,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        rec = DocumentRecord.objects.filter(doc_id=document_id).first()
        if not rec:
            return Response(
                {
                    "status": "invalid",
                    "message": "Document ID not found.",
                    "chain_verification": chain_verification,
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        if version_no_raw:
            if not version_no_raw.isdigit():
                return Response(
                    {
                        "status": "invalid",
                        "message": "version_no must be numeric.",
                        "chain_verification": chain_verification,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            version = rec.versions.filter(version_no=int(version_no_raw)).first()
        else:
            version = rec.versions.order_by("-version_no").first()

        if not version or not hasattr(version, "artifact"):
            return Response(
                {
                    "status": "invalid",
                    "message": "Stored signed artifact not found.",
                    "chain_verification": chain_verification,
                },
                status=status.HTTP_404_NOT_FOUND,
            )

        artifact = version.artifact
        current_bytes = current_file.read()
        original_bytes = bytes(artifact.original_bytes)

        # Primary cryptographic check: verify stored signature against stored original bytes.
        cert = x509.load_pem_x509_certificate(artifact.certificate_pem.encode("utf-8"))
        signature_bytes = base64.b64decode(artifact.signature_b64, validate=True)
        pub = cert.public_key()
        if artifact.algorithm == "RSA-SHA256":
            pub.verify(signature_bytes, original_bytes, padding.PKCS1v15(), hashes.SHA256())
        elif artifact.algorithm == "ECDSA-P256-SHA256":
            pub.verify(signature_bytes, original_bytes, ec.ECDSA(hashes.SHA256()))
        else:
            return Response(
                {
                    "status": "invalid",
                    "message": "Unsupported stored algorithm.",
                    "chain_verification": chain_verification,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if current_bytes == original_bytes:
            return Response(
                {
                    "status": "valid",
                    "message": "Document Integrity Verified",
                    "document_id": document_id,
                    "version_no": version.version_no,
                    "chain_verification": chain_verification,
                }
            )

        tamper_report, err_msg = _localize_tamper(original_bytes, current_bytes, artifact.original_filename or current_file.name)
        if tamper_report is None:
            return Response(
                {
                    "status": "tampered",
                    "message": "Document modified",
                    "tamper_report": {"added": [], "deleted": [], "modified": []},
                    "note": err_msg or "Signature mismatch detected.",
                    "document_id": document_id,
                    "version_no": version.version_no,
                    "chain_verification": chain_verification,
                }
            )
        return Response(
            {
                "status": "tampered",
                "message": "Document modified",
                "tamper_report": tamper_report,
                "document_id": document_id,
                "version_no": version.version_no,
                "chain_verification": chain_verification,
            }
        )
    except Exception as e:
        return Response(
            {
                "status": "failed",
                "message": str(e),
                "chain_verification": _build_chain_verification(str(request.data.get("document_id", "")).strip()),
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@parser_classes([MultiPartParser, FormParser])
@permission_classes([AllowAny])
def verify_and_watermark(request):
    """
    Verify signed package and return a verified ZIP artifact bundle:
      - original reconstructed file
      - verification_manifest.json (HMAC sealed for tamper evidence)
      - verification_receipt.pdf
      - verified_watermarked.pdf (if original is PDF)
    """
    try:
        file_obj = request.FILES.get("file")
        chain_verification = _build_chain_verification(None)
        if not file_obj:
            return Response(
                {
                    "status": "invalid",
                    "message": "No signed package file uploaded.",
                    "chain_verification": chain_verification,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            package_bytes = file_obj.read()
            package = json.loads(package_bytes.decode("utf-8"))
            chain_verification = _build_chain_verification(
                str(package.get("document_id") or "").strip()
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            return Response(
                {
                    "status": "invalid",
                    "message": "File is not valid JSON.",
                    "chain_verification": chain_verification,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        ok, details = _verify_signed_package(package, request)
        if not ok:
            failed_details = dict(details)
            failed_details["chain_verification"] = _build_chain_verification(
                str(package.get("document_id") or "").strip()
            )
            return Response(failed_details)

        document_bytes = details["document_bytes"]
        signed_by = details.get("signed_by", "")
        signed_ts = details.get("timestamp", "")
        cert_owner = details.get("certificate_owner", "")
        cert_expiry = details.get("certificate_valid_until", "")
        algo = details.get("algorithm", "RSA-SHA256")
        digest = details.get("hash", "")
        original_filename = (details.get("original_filename") or "").strip() or "original_document.bin"
        verification_ts = datetime.now(timezone.utc).isoformat()
        document_id = (details.get("document_id") or "").strip()

        chain_info = {"document_id": document_id, "version_no": None, "chain_hash": "", "chain_ok": False}
        if document_id:
            record = DocumentRecord.objects.filter(doc_id=document_id).first()
            if record:
                latest = record.versions.order_by("-version_no").first()
                if latest:
                    expected_chain_hash = _compute_chain_hash(
                        latest.prev_chain_hash,
                        latest.payload_hash,
                        latest.algorithm,
                        latest.signature_b64,
                        latest.created_at.isoformat(),
                    )
                    chain_info = {
                        "document_id": document_id,
                        "version_no": latest.version_no,
                        "chain_hash": latest.chain_hash,
                        "chain_ok": expected_chain_hash == latest.chain_hash,
                    }

        qr_payload = {
            "document_id": document_id,
            "hash": digest,
            "signed_by": signed_by,
            "verified_at": verification_ts,
            "exp_unix": int(time.time()) + 60 * 60 * 24 * 30,
        }
        qr_token = _create_qr_token(qr_payload)

        receipt_payload = {
            "status": "Signature Valid",
            "signed_by": signed_by,
            "certificate_owner": cert_owner,
            "certificate_valid_until": cert_expiry,
            "signed_timestamp": signed_ts,
            "verified_at": verification_ts,
            "algorithm": algo,
            "sha256_hash": digest,
            "document_id": document_id,
            "source_package": file_obj.name,
            "immutable_note": "Manifest is tamper-evident via HMAC seal",
            "qr_token": qr_token,
            "chain": chain_info,
        }
        manifest_payload = {
            "version": "1.0",
            "type": "verification_manifest",
            "verification": receipt_payload,
            "original_filename": original_filename,
            "original_size_bytes": len(document_bytes),
            "signed_package_sha256": sha256(package_bytes).hexdigest(),
        }
        manifest_payload["integrity_seal"] = _manifest_seal(manifest_payload)

        receipt_pdf_bytes = _build_receipt_pdf(receipt_payload)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(original_filename, document_bytes)
            zf.writestr(
                "verification_manifest.json",
                json.dumps(manifest_payload, indent=2, ensure_ascii=False),
            )
            zf.writestr("verification_receipt.pdf", receipt_pdf_bytes)
            zf.writestr("qr_token.txt", qr_token)

            try:
                import qrcode

                qr_img = qrcode.make(qr_token)
                qr_buffer = io.BytesIO()
                qr_img.save(qr_buffer, format="PNG")
                zf.writestr("verification_qr.png", qr_buffer.getvalue())
            except Exception:
                pass

            if original_filename.lower().endswith(".pdf"):
                watermark_lines = [
                    f"VERIFIED: {signed_by or cert_owner}",
                    f"Signed: {signed_ts}",
                    f"Verified: {verification_ts}",
                    f"Algorithm: {algo}",
                    f"SHA-256: {digest[:20]}...",
                ]
                try:
                    watermarked_pdf = _watermark_pdf_bytes(document_bytes, watermark_lines)
                    zf.writestr("verified_watermarked.pdf", watermarked_pdf)
                except Exception:
                    # Keep universal artifacts even if PDF watermarking fails.
                    pass

        zip_buffer.seek(0)
        response = HttpResponse(zip_buffer.read(), content_type="application/zip")
        response["Content-Disposition"] = 'attachment; filename="verified_artifacts.zip"'
        return response
    except Exception as e:
        return Response(
            {
                "status": "failed",
                "message": str(e),
                "chain_verification": chain_verification,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


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


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def logs(request):
    profile = ensure_user_profile(request.user)
    qs = AuditLog.objects.all() if profile.role == profile.Role.ADMIN else AuditLog.objects.filter(user=request.user)
    return Response(AuditLogSerializer(qs, many=True).data)


# ---------------------------------------------------------------------------
#  VERIFY endpoint — supports both file and text input
# ---------------------------------------------------------------------------

@api_view(["POST"])
@parser_classes([JSONParser, MultiPartParser, FormParser])
@permission_classes([AllowAny])
def verify(request):
    """
    Verify endpoint: accepts data OR file, signature (base64), and public_key (PEM).
    Returns success/failed status.
    """
    try:
        signature = str(request.data.get("signature", "")).strip()
        public_key_raw = str(request.data.get("public_key", "")).strip()
        document_id = str(request.data.get("document_id", "")).strip()
        chain_verification = _build_chain_verification(document_id)

        if not signature or not public_key_raw:
            return Response(
                {
                    "status": "failed",
                    "message": "Both 'signature' and 'public_key' are required.",
                    "chain_verification": chain_verification,
                }
            )

        # Extract input — handles BOTH file and text (NO .decode() on file!)
        data_bytes, _, _ = _extract_input_bytes(request)

        computed_hash = sha256_hex(data_bytes)

        # Support cert or raw pubkey
        pub_pem = public_key_raw
        if public_key_raw.startswith('-----BEGIN CERTIFICATE-----'):
            try:
                pub_pem = extract_pub_from_cert(public_key_raw)
            except Exception:
                return Response(
                    {
                        "status": "failed",
                        "message": "Invalid certificate",
                        "chain_verification": chain_verification,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            pub_pem, err = normalize_external_public_key_pem(public_key_raw)
            if err:
                if request.user.is_authenticated:
                    AuditLog.objects.create(
                        user=request.user,
                        action=AuditLog.Action.VERIFY,
                        status=AuditLog.Status.FAILED,
                        data_hash=computed_hash,
                        ip_address=_request_ip(request),
                        failure_reason=err,
                    )
                return Response(
                    {
                        "status": "failed",
                        "message": err,
                        "chain_verification": chain_verification,
                    }
                )

        try:
            verify_algorithm = _algorithm_from_public_key_pem(pub_pem)
        except Exception:
            return Response(
                {
                    "status": "failed",
                    "message": "Unsupported public key type",
                    "chain_verification": chain_verification,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        ok = verify_signature_with_algorithm(pub_pem, signature, data_bytes, verify_algorithm)
        if request.user.is_authenticated:
            AuditLog.objects.create(
                user=request.user,
                action=AuditLog.Action.VERIFY,
                status=AuditLog.Status.SUCCESS if ok else AuditLog.Status.FAILED,
                data_hash=computed_hash,
                ip_address=_request_ip(request),
                failure_reason="" if ok else "Invalid signature or tampered data",
            )
        if ok:
            return Response(
                {
                    "status": "success",
                    "chain_verification": chain_verification,
                }
            )
        return Response(
            {
                "status": "failed",
                "message": "Invalid signature",
                "chain_verification": chain_verification,
            }
        )

    except Exception as e:
        return Response(
            {
                "status": "failed",
                "message": str(e),
                "chain_verification": _build_chain_verification(
                    str(request.data.get("document_id", "")).strip()
                ),
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def my_public_key(request):
    try:
        profile = ensure_user_profile(request.user)
        # Return user's self-signed certificate (PEM). Never expose private keys.
        certificate_pem = (profile.certificate or "").strip() or (profile.certificate_pem or "").strip()
        response_data = {
            "username": request.user.username,
            "role": profile.role,
            "certificate": certificate_pem,
            "signature_algorithm": profile.signature_algorithm,
        }
        return Response(response_data)
    except Exception as e:
        return Response(
            {
                "status": "failed",
                "message": str(e),
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def set_signature_algorithm(request):
    algorithm = str(request.data.get("signature_algorithm", "")).strip()
    if algorithm not in {"RSA-SHA256", "ECDSA-P256-SHA256"}:
        return Response(
            {"detail": "signature_algorithm must be RSA-SHA256 or ECDSA-P256-SHA256."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    profile = ensure_user_profile(request.user, preferred_algorithm=algorithm)
    return Response(
        {
            "status": "success",
            "username": request.user.username,
            "signature_algorithm": profile.signature_algorithm,
            "message": "Signing algorithm updated.",
        }
    )


@api_view(["GET"])
@permission_classes([AllowAny])
def supported_algorithms(request):
    return Response(
        {
            "algorithms": [
                {"id": "RSA-SHA256", "label": "RSA-SHA256"},
                {"id": "ECDSA-P256-SHA256", "label": "ECDSA-P256-SHA256"},
            ]
        }
    )


@api_view(["GET"])
def timestamp(request):
    """Mock Timestamp Authority endpoint."""
    token = mock_timestamp_token()
    return Response({
        "timestamp_token": token,
        "ts_unix": int(time.time())
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def benchmark_crypto(request):
    """
    Step-1 benchmarking endpoint for supported algorithms.
    Payload:
      - runs (optional, default 20, max 200)
      - payload (optional text, default sample sentence)
    """
    runs_raw = request.data.get("runs", 20)
    payload_raw = request.data.get(
        "payload",
        "Digital signature benchmark payload for RSA and ECDSA performance testing.",
    )
    try:
        runs = int(runs_raw)
    except Exception:
        return Response({"detail": "runs must be an integer."}, status=status.HTTP_400_BAD_REQUEST)
    if runs < 1 or runs > 200:
        return Response({"detail": "runs must be between 1 and 200."}, status=status.HTTP_400_BAD_REQUEST)

    payload_bytes = str(payload_raw).encode("utf-8")
    results = [
        _benchmark_algorithm("RSA-SHA256", payload_bytes, runs),
        _benchmark_algorithm("ECDSA-P256-SHA256", payload_bytes, runs),
    ]
    fastest_sign = min(results, key=lambda x: x["sign_ms_avg"])["algorithm"]
    fastest_verify = min(results, key=lambda x: x["verify_ms_avg"])["algorithm"]
    return Response(
        {
            "runs": runs,
            "payload_size_bytes": len(payload_bytes),
            "results": results,
            "summary": {
                "fastest_sign": fastest_sign,
                "fastest_verify": fastest_verify,
            },
        }
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def verify_chain(request):
    doc_id = (request.query_params.get("document_id") or "").strip()
    if not doc_id:
        return Response({"detail": "document_id is required."}, status=status.HTTP_400_BAD_REQUEST)
    record = DocumentRecord.objects.filter(doc_id=doc_id).first()
    if not record:
        return Response({"status": "missing", "message": "Document chain not found."}, status=status.HTTP_404_NOT_FOUND)

    versions = list(record.versions.order_by("version_no"))
    issues: list[dict] = []
    prev_chain = ""
    for v in versions:
        if v.prev_chain_hash != prev_chain:
            issues.append(
                {
                    "version_no": v.version_no,
                    "issue": "prev_chain_hash mismatch",
                    "expected_prev": prev_chain,
                    "actual_prev": v.prev_chain_hash,
                }
            )
        expected = _compute_chain_hash(
            v.prev_chain_hash,
            v.payload_hash,
            v.algorithm,
            v.signature_b64,
            v.created_at.isoformat(),
        )
        if expected != v.chain_hash:
            issues.append(
                {
                    "version_no": v.version_no,
                    "issue": "chain_hash mismatch",
                    "expected": expected,
                    "actual": v.chain_hash,
                }
            )
        prev_chain = v.chain_hash

    return Response(
        {
            "document_id": doc_id,
            "versions": len(versions),
            "chain_valid": len(issues) == 0,
            "issues": issues,
        }
    )


@api_view(["GET"])
@permission_classes([AllowAny])
def verify_qr(request):
    token = (request.query_params.get("token") or "").strip()
    if not token:
        return Response({"detail": "token is required."}, status=status.HTTP_400_BAD_REQUEST)
    ok, payload_or_err = _verify_qr_token(token)
    if not ok:
        return Response({"status": "invalid", "message": payload_or_err}, status=status.HTTP_400_BAD_REQUEST)
    payload = payload_or_err
    return Response({"status": "valid", "payload": payload})


@api_view(["POST"])
@parser_classes([MultiPartParser, FormParser, JSONParser])
@permission_classes([AllowAny])
def integrity_report(request):
    """
    Unified integrity framework endpoint:
      - verifies signed package cryptographically
      - optionally localizes tampering against provided compare JSON/file
      - validates append-only chain for document_id (if present)
    """
    package_file = request.FILES.get("file")
    if not package_file:
        return Response({"detail": "Signed package file is required."}, status=status.HTTP_400_BAD_REQUEST)
    try:
        package = json.loads(package_file.read().decode("utf-8"))
    except Exception:
        return Response({"detail": "Invalid signed package JSON."}, status=status.HTTP_400_BAD_REQUEST)

    ok, details = _verify_signed_package(package, request)
    # For localization we can still use structured snapshot from the package even if signature is invalid.
    package_structured_snapshot = package.get("structured_snapshot")
    package_version_no = str(package.get("version_no", "") or "").strip()
    report: dict = {
        "crypto_verification": {
            "status": "valid" if ok else "invalid",
            "details": {k: v for k, v in details.items() if k not in {"document_bytes", "certificate_pem"}},
        },
        "tamper_localization": {
            "status": "not_requested",
            "added_fields": [],
            "deleted_fields": [],
            "modified_fields": [],
            "summary": {"added_count": 0, "deleted_count": 0, "modified_count": 0},
        },
        "chain_verification": {"status": "not_applicable"},
    }

    document_id = str(details.get("document_id", "")).strip() if isinstance(details, dict) else ""
    # Fall back to package document_id if crypto verification failed.
    if not document_id:
        document_id = str(package.get("document_id", "") or "").strip()
    if document_id:
        rec = DocumentRecord.objects.filter(doc_id=document_id).first()
        if rec:
            versions = list(rec.versions.order_by("version_no"))
            chain_ok = True
            prev = ""
            for v in versions:
                expected = _compute_chain_hash(
                    v.prev_chain_hash,
                    v.payload_hash,
                    v.algorithm,
                    v.signature_b64,
                    v.created_at.isoformat(),
                )
                if v.prev_chain_hash != prev or expected != v.chain_hash:
                    chain_ok = False
                    break
                prev = v.chain_hash
            report["chain_verification"] = {
                "status": "valid" if chain_ok else "invalid",
                "document_id": document_id,
                "versions": len(versions),
            }
        else:
            report["chain_verification"] = {
                "status": "missing",
                "document_id": document_id,
            }

    # Automatic tamper localization:
    # expected_snapshot comes from DB (trusted) when document_id+version_no exist.
    # actual_snapshot is derived from uploaded signed package's current document bytes.
    expected_snapshot = ""
    if document_id and package_version_no.isdigit():
        rec = DocumentRecord.objects.filter(doc_id=document_id).first()
        if rec:
            v = rec.versions.filter(version_no=int(package_version_no)).first()
            if v:
                expected_snapshot = str((v.metadata_json or {}).get("structured_snapshot") or "").strip()

    # As a fallback (if DB snapshot missing), we can still attempt using the package snapshot,
    # but that is not trusted if the package was tampered.
    if not expected_snapshot:
        expected_snapshot = str(package_structured_snapshot or "").strip()

    actual_snapshot = ""
    try:
        doc_b64 = str(package.get("document") or "").strip()
        if doc_b64:
            doc_bytes = base64.b64decode(doc_b64, validate=True)
            actual_snapshot = str(_canonical_json_text_from_bytes(doc_bytes) or "").strip()
    except Exception:
        actual_snapshot = ""

    compare_json_text = str(request.data.get("compare_json", "")).strip()
    compare_file = request.FILES.get("compare_file")
    # If caller explicitly provided original JSON, treat it as expected_snapshot override.
    if compare_file:
        try:
            compare_json_text = compare_file.read().decode("utf-8")
        except Exception:
            compare_json_text = ""
    if compare_json_text:
        expected_snapshot = compare_json_text.strip()

    if expected_snapshot and actual_snapshot:
        try:
            diff = _json_localization_diff(expected_snapshot, actual_snapshot)
            report["tamper_localization"] = {"status": "computed", **diff}
        except Exception as e:
            report["tamper_localization"] = {
                "status": "failed",
                "message": f"Could not localize tampering: {e}",
            }
    else:
        report["tamper_localization"] = {
            "status": "not_applicable",
            "message": "Automatic localization requires structured JSON and a stored snapshot (document_id + version_no).",
        }

    top_status = "valid"
    if report["crypto_verification"]["status"] != "valid":
        top_status = "invalid"
    elif report["chain_verification"].get("status") == "invalid":
        top_status = "invalid"
    report["status"] = top_status
    return Response(report)

@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def export_signed(request):
    if request.method == "GET":
        export_type = (request.query_params.get("type") or "").strip().lower()
        fmt = (request.query_params.get("format") or "json").strip().lower()
        if export_type not in {"logs", "signed_data"}:
            return Response({"detail": "type must be 'logs' or 'signed_data'."}, status=status.HTTP_400_BAD_REQUEST)
        if fmt not in {"json", "csv"}:
            return Response({"detail": "format must be 'json' or 'csv'."}, status=status.HTTP_400_BAD_REQUEST)

        profile = ensure_user_profile(request.user)
        is_admin = profile.role == profile.Role.ADMIN
        if export_type == "logs":
            qs = AuditLog.objects.all() if is_admin else AuditLog.objects.filter(user=request.user)
            data_rows = [
                {
                    "username": row.user.username,
                    "action": row.action,
                    "status": row.status,
                    "timestamp": row.timestamp.isoformat(),
                    "data_hash": row.data_hash,
                    "ip_address": row.ip_address or "",
                    "failure_reason": row.failure_reason or "",
                }
                for row in qs
            ]
            filename = "logs_admin" if is_admin else "logs_user"
        else:
            qs = SignatureLog.objects.filter(user=request.user)
            data_rows = [_export_payload(row) for row in qs]
            filename = "signed_data"

        if fmt == "json":
            response = HttpResponse(
                json.dumps({"type": export_type, "items": data_rows}, indent=2),
                content_type="application/json",
            )
            response["Content-Disposition"] = f'attachment; filename="{filename}.json"'
            return response

        buffer = io.StringIO()
        writer = csv.writer(buffer)
        if export_type == "logs":
            headers = ["username", "action", "status", "timestamp", "data_hash", "ip_address", "failure_reason"]
        else:
            headers = ["data", "username", "timestamp", "hash", "signature", "public_key"]
        writer.writerow(headers)
        for item in data_rows:
            writer.writerow([item.get(k, "") for k in headers])
        response = HttpResponse(buffer.getvalue(), content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="{filename}.csv"'
        return response

    serializer = ExportRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    fmt = serializer.validated_data["format"]
    log_id = serializer.validated_data["log_id"]

    log = get_object_or_404(SignatureLog, pk=log_id, user=request.user)
    body = _export_payload(log)

    if fmt == "json":
        response = HttpResponse(
            json.dumps(body, indent=2),
            content_type="application/json",
        )
        response["Content-Disposition"] = f'attachment; filename="signature_{log_id}.json"'
        return response

    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            ["data", "username", "timestamp", "hash", "signature", "public_key"]
        )
        writer.writerow(
            [
                body["data"],
                body["username"],
                body["timestamp"],
                body["hash"],
                body["signature"],
                body["public_key"],
            ]
        )
        response = HttpResponse(buffer.getvalue(), content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="signature_{log_id}.csv"'
        return response

    wb = Workbook()
    ws = wb.active
    ws.title = "Signed"
    ws.append(["Field", "Value"])
    for key in ("data", "username", "timestamp", "hash", "signature", "public_key"):
        ws.append([key, body[key]])
    out = io.BytesIO()
    wb.save(out)
    out.seek(0)
    response = HttpResponse(
        out.read(),
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    response["Content-Disposition"] = f'attachment; filename="signature_{log_id}.xlsx"'
    return response
