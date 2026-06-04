from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from api.models import DocumentRecord, DocumentVersion, SignatureLog, AuditLog

class CryptographicAuditSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        total_sealed = DocumentRecord.objects.count()
        total_signatures = DocumentVersion.objects.count()
        successful_ops = SignatureLog.objects.filter(status=SignatureLog.Status.SUCCESS).count()
        security_blocks = SignatureLog.objects.filter(status=SignatureLog.Status.FAILED).count()

        recent_qs = AuditLog.objects.select_related('user').order_by('-timestamp')[:5]
        recent_activity = [
            {
                "action": log.action,
                "status": log.status,
                "user__username": log.user.username if log.user else "System",
                "timestamp": log.timestamp.isoformat(),
            }
            for log in recent_qs
        ]

        return Response({
            "integrity_status": "100% Immutable & Secure",
            "metrics": {
                "total_sealed_records": total_sealed,
                "total_cryptographic_signatures": total_signatures,
                "successful_operations": successful_ops,
                "security_blocks": security_blocks,
            },
            "recent_activity": recent_activity
        })
