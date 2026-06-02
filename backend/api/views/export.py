"""Export and utility views: export_signed, logs, benchmark_crypto."""
from __future__ import annotations

import csv
import io
import json

from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from openpyxl import Workbook
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from ..key_utils import ensure_user_profile
from ..models import AuditLog, SignatureLog
from ..serializers import AuditLogSerializer, ExportRequestSerializer

from ._helpers import _benchmark_algorithm, _export_payload


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def logs(request):
    profile = ensure_user_profile(request.user)
    qs = AuditLog.objects.all() if profile.role == profile.Role.ADMIN else AuditLog.objects.filter(user=request.user)
    return Response(AuditLogSerializer(qs, many=True).data)


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
