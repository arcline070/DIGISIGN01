"""Shared helper functions used by multiple view modules."""
from __future__ import annotations

import base64
import hmac
import io
import json
import time
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from statistics import mean

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID
from django.conf import settings

from ..crypto_utils import (
    create_key_pair,
    extract_pub_from_cert,
    normalize_external_public_key_pem,
    sha256_hex,
    sign_data_with_algorithm,
    verify_signature_with_algorithm,
)
from ..key_utils import decrypt_private_key, ensure_user_profile
from ..models import (
    AuditLog,
    DocumentRecord,
    DocumentVersion,
    SignatureLog,
    SignedDocumentArtifact,
)
from ..services import create_document_version, ChainForkError
from ..utils.chain_audit import verify_entire_chain
from ..utils.crypto import compute_chain_hash as _compute_chain_hash_util
from ..utils.diff_engine import detect_changes


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

    MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
    if file_obj and hasattr(file_obj, "size") and file_obj.size > MAX_UPLOAD_BYTES:
        raise ValueError(
            f"File too large ({file_obj.size:,} bytes). Maximum allowed is {MAX_UPLOAD_BYTES:,} bytes."
        )

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
    
    if name.endswith(".xlsx") or name.endswith(".xls"):
        try:
            import math
            import pandas as pd
            df_dict = pd.read_excel(io.BytesIO(data_bytes), sheet_name=None)
            out = {}
            for sheet, df in df_dict.items():
                records = df.to_dict(orient="records")
                # Sanitize every cell: NaN, Inf → None, Timestamp → ISO string
                clean_records = []
                for row in records:
                    clean_row = {}
                    for k, v in row.items():
                        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                            clean_row[k] = None
                        elif hasattr(v, 'isoformat'):
                            val = v.isoformat()
                            if '+' not in val and not val.endswith('Z'):
                                if '.' not in val:
                                    val += '.000'
                                val += 'Z'
                            clean_row[k] = val
                        else:
                            clean_row[k] = v
                    clean_records.append(clean_row)
                out[sheet] = clean_records
            return json.dumps(out, sort_keys=True, indent=2, ensure_ascii=False, default=str), "json"
        except Exception as e:
            return None, f"Excel parsing failed: {e}"

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
    from ..utils.diff_engine import localize_tampering
    expected_obj = json.loads(expected_json_text)
    actual_obj = json.loads(actual_json_text)
    report = localize_tampering(expected_obj, actual_obj)
    return {
        "added_fields": list(report["added"].keys()),
        "deleted_fields": list(report["deleted"].keys()),
        "modified_fields": list(report["modified"].keys()),
        "summary": {
            "added_count": len(report["added"]),
            "deleted_count": len(report["deleted"]),
            "modified_count": len(report["modified"]),
        },
    }


def _json_tamper_report(original_text: str, current_text: str) -> dict:
    from ..utils.diff_engine import localize_tampering
    original_obj = json.loads(original_text)
    current_obj = json.loads(current_text)
    return localize_tampering(original_obj, current_obj)


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
        return None, f"Localization failed: Original={original_kind}, Current={current_kind}"

    kind = "json" if original_kind == "json" or current_kind == "json" else (
        "csv" if original_kind == "csv" or current_kind == "csv" else "text"
    )

    if kind == "json":
        return _json_tamper_report(original_text, current_text), None

    if kind == "csv":
        import csv, io
        from ..utils.diff_engine import localize_tampering
        try:
            r1 = list(csv.reader(io.StringIO(original_text)))
            r2 = list(csv.reader(io.StringIO(current_text)))
            return localize_tampering(r1, r2, path="Row"), None
        except Exception:
            # Fall back to text line-based diff if CSV parsing fails
            pass

    # text line-based diff
    report = detect_changes(original_text, current_text)
    return report, None


def _alg_spec_from_package(signature_algorithm: str) -> tuple[str, str]:
    """
    Map package algorithm labels to internal profile algorithm + key type.
    Returns (internal_algorithm, key_type) where key_type in {"rsa","ecdsa"}.
    """
    alg = (signature_algorithm or "").strip()
    if alg in ["RSA-PKCS1v15", "RSA-PSS"]:
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
    """Delegate to the canonical implementation in utils.crypto."""
    return _compute_chain_hash_util(
        prev_chain_hash, payload_hash, algorithm, signature_b64, timestamp_iso
    )


def _build_chain_verification(document_id: str | None) -> dict:
    """
    PHASE 3: Chronological Chain Verification  (now delegates to deep auditor)

    Uses ``verify_entire_chain`` from ``utils.chain_audit`` to perform a full
    mathematical traversal from H_0 → H_n, then returns the legacy dict shape
    so all existing callers remain compatible.
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

    report = verify_entire_chain(rec.pk)
    chain_verification["verified_versions"] = report.total_versions
    chain_verification["status"] = "valid" if report.is_valid else "invalid"
    chain_verification["broken_at_version"] = report.broken_at_version
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

    Now delegates to ``services.create_document_version`` which wraps the
    entire operation in ``transaction.atomic()`` with ``select_for_update()``
    row locking to prevent the forking race condition.
    """
    return create_document_version(
        user=user,
        doc_id=doc_id,
        payload_hash=payload_hash,
        algorithm=algorithm,
        certificate_pem=certificate_pem,
        signature_b64=signature_b64,
        metadata=metadata,
    )


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
        now_utc = datetime.now(timezone.utc)
        if cert.not_valid_before_utc > now_utc or cert.not_valid_after_utc < now_utc:
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
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
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
        "certificate_valid_until": cert.not_valid_after_utc.date().isoformat() if cert is not None else "",
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
