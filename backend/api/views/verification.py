"""Verification views: verify_document, verify_stored_document, verify_and_watermark, verify_chain, verify_qr, integrity_report, verify."""
from __future__ import annotations

import base64
import io
import json
import time
import zipfile
from datetime import datetime, timezone
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID
from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.http import HttpResponse

from ..crypto_utils import (
    extract_pub_from_cert,
    normalize_external_public_key_pem,
    sha256_hex,
    verify_signature_with_algorithm,
)
from ..key_utils import ensure_user_profile
from ..models import AuditLog, DocumentRecord
from ..utils.chain_audit import verify_entire_chain

from ._helpers import (
    _algorithm_from_public_key_pem,
    _build_chain_verification,
    _build_receipt_pdf,
    _build_verification_details,
    _canonical_json_text_from_bytes,
    _compute_chain_hash,
    _create_qr_token,
    _extract_input_bytes,
    _json_localization_diff,
    _localize_tamper,
    _manifest_seal,
    _request_ip,
    _verify_qr_token,
    _verify_signed_package,
    _watermark_pdf_bytes,
)


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
        # not only the DB baseline. This makes the UI properly detect "chain breaks" even when the uploaded
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
                        expected_prev = settings.HASH_CHAIN_GENESIS if v_no == 1 else versions[idx - 1].chain_hash

                        # Expected chain_hash based on DB immutable fields.
                        expected_chain_hash = _compute_chain_hash(
                            prev_chain_hash=expected_prev,
                            payload_hash=db_version.payload_hash,
                            algorithm=db_version.algorithm,
                            signature_b64=db_version.signature_b64,
                            timestamp_iso=db_version.created_at.isoformat(),
                        )

                        # If the uploaded package's chain linkage is inconsistent, mark chain invalid.
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
        from cryptography import x509 as _x509
        cert = _x509.load_pem_x509_certificate(artifact.certificate_pem.encode("utf-8"))
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


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def verify_chain(request):
    doc_id = (request.query_params.get("document_id") or "").strip()
    if not doc_id:
        return Response({"detail": "document_id is required."}, status=status.HTTP_400_BAD_REQUEST)
    record = DocumentRecord.objects.filter(doc_id=doc_id).first()
    if not record:
        return Response({"status": "missing", "message": "Document chain not found."}, status=status.HTTP_404_NOT_FOUND)

    report = verify_entire_chain(record.pk)
    issues = [
        {"version_no": e.version_no, "issue": e.reason}
        for e in report.entries
        if not e.valid
    ]

    return Response(
        {
            "document_id": doc_id,
            "versions": report.total_versions,
            "chain_valid": report.is_valid,
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
            chain_report = verify_entire_chain(rec.pk)
            report["chain_verification"] = {
                "status": "valid" if chain_report.is_valid else "invalid",
                "document_id": document_id,
                "versions": chain_report.total_versions,
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
