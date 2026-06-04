from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.contrib.auth import get_user_model
from api.models import DocumentRecord, DocumentVersion, AuditLog, UserProfile

User = get_user_model()

class DashboardSummaryView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request, *args, **kwargs):
        # Metrics
        total_uploads = DocumentRecord.objects.count()
        signatures_minted = DocumentVersion.objects.count()
        active_users = User.objects.filter(is_active=True).count()

        # Audit Ledger (last 10)
        recent_logs = AuditLog.objects.select_related('user').order_by('-timestamp')[:10]
        audit_ledger = [
            {
                "timestamp": log.timestamp.isoformat(),
                "user": log.user.username if log.user else "System",
                "action": log.action,
                "status": log.status,
                "failure_reason": log.failure_reason,
            }
            for log in recent_logs
        ]

        # Algorithm Split
        rsa_count = UserProfile.objects.filter(signature_algorithm="RSA-SHA256").count()
        ecdsa_count = UserProfile.objects.filter(signature_algorithm="ECDSA-P256-SHA256").count()

        return Response({
            "metrics": {
                "total_uploads": total_uploads,
                "signatures_minted": signatures_minted,
                "active_users": active_users,
            },
            "audit_ledger": audit_ledger,
            "algorithm_split": {
                "RSA": rsa_count,
                "ECDSA": ecdsa_count
            }
        })

class UserRosterView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request, *args, **kwargs):
        users = User.objects.all().values('username', 'is_staff', 'is_active', 'last_login')
        roster = []
        for u in users:
            roster.append({
                "username": u['username'],
                "is_staff": u['is_staff'],
                "is_active": u['is_active'],
                "last_login": u['last_login'].isoformat() if u['last_login'] else None,
            })
        return Response({"users": roster})

class MakerCheckerView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request, *args, **kwargs):
        pending_docs = DocumentRecord.objects.filter(status=DocumentRecord.StatusChoices.PENDING).values(
            'doc_id', 'owner__username', 'created_at', 'status'
        )
        data = [
            {
                "doc_id": doc['doc_id'],
                "owner": doc['owner__username'],
                "created_at": doc['created_at'].isoformat(),
                "status": doc['status']
            }
            for doc in pending_docs
        ]
        return Response({"pending_documents": data})

    def post(self, request, *args, **kwargs):
        doc_id = request.data.get('document_id')
        new_status = request.data.get('new_status')

        if not doc_id or new_status not in [DocumentRecord.StatusChoices.APPROVED, DocumentRecord.StatusChoices.REJECTED]:
            return Response({"error": "Invalid request. Provide valid document_id and new_status ('APPROVED' or 'REJECTED')."}, status=400)

        try:
            doc = DocumentRecord.objects.get(doc_id=doc_id)
            old_status = doc.status
            doc.status = new_status
            doc.save()

            AuditLog.objects.create(
                user=request.user,
                action=AuditLog.Action.SIGN,  # Best fit for action tracking or custom
                status=AuditLog.Status.SUCCESS,
                data_hash=doc.doc_id,
                ip_address=request.META.get('REMOTE_ADDR'),
                failure_reason=f"Status changed from {old_status} to {new_status}"
            )
            return Response({"message": f"Document {doc_id} status updated to {new_status}."})
        except DocumentRecord.DoesNotExist:
            return Response({"error": "Document not found."}, status=404)
