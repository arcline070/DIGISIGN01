import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone


class UserProfile(models.Model):
    class Role(models.TextChoices):
        ADMIN = "admin", "Admin"
        USER = "user", "User"

    class SignatureAlgorithm(models.TextChoices):
        RSA = "RSA-SHA256", "RSA-SHA256"
        ECDSA = "ECDSA-P256-SHA256", "ECDSA-P256-SHA256"

    # In production, private keys should be stored in HSM or Key Vault.
    # This implementation uses encrypted storage for demonstration.
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    public_key = models.TextField()
    private_key = models.TextField()
    # Self-signed X.509 certificate (PEM) for this user. Contains the public key only.
    certificate = models.TextField(blank=True, default="")
    certificate_pem = models.TextField(blank=True, default='')
    signature_algorithm = models.CharField(
        max_length=32,
        choices=SignatureAlgorithm.choices,
        default=SignatureAlgorithm.RSA,
    )
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.USER)

    class Meta:
        verbose_name = "User profile"

    def __str__(self):
        return f"Profile for {self.user.username}"


class SignatureLog(models.Model):
    class Action(models.TextChoices):
        SIGN = "SIGN", "SIGN"
        VERIFY = "VERIFY", "VERIFY"

    class Status(models.TextChoices):
        SUCCESS = "SUCCESS", "SUCCESS"
        FAILED = "FAILED", "FAILED"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="signature_logs",
    )
    action = models.CharField(max_length=16, choices=Action.choices, default=Action.SIGN)
    data_hash = models.CharField(max_length=64, default="", db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.SUCCESS)
    data = models.TextField()
    hash_hex = models.CharField(max_length=64)
    signature = models.TextField(blank=True)
    public_key = models.TextField()

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.user.username} @ {self.timestamp}"


class AuditLog(models.Model):
    class Action(models.TextChoices):
        SIGN = "SIGN", "SIGN"
        VERIFY = "VERIFY", "VERIFY"

    class Status(models.TextChoices):
        SUCCESS = "SUCCESS", "SUCCESS"
        FAILED = "FAILED", "FAILED"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="audit_logs",
    )
    action = models.CharField(max_length=16, choices=Action.choices)
    status = models.CharField(max_length=16, choices=Status.choices)
    data_hash = models.CharField(max_length=64, db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    failure_reason = models.TextField(blank=True)

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.user.username} {self.action} {self.status}"


class DocumentRecord(models.Model):
    """
    Logical document stream (append-only versions).
    """

    class StatusChoices(models.TextChoices):
        PENDING = "PENDING", "Pending"
        APPROVED = "APPROVED", "Approved"
        REJECTED = "REJECTED", "Rejected"

    doc_id = models.CharField(max_length=128, unique=True)
    verification_token = models.UUIDField(default=uuid.uuid4, unique=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="document_records",
    )
    created_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(
        max_length=20, 
        choices=StatusChoices.choices, 
        default=StatusChoices.APPROVED
    )

    def __str__(self):
        return f"{self.doc_id} ({self.owner.username})"


class DocumentVersion(models.Model):
    """
    Immutable append-only version entry with hash chaining.
    """

    record = models.ForeignKey(
        DocumentRecord,
        on_delete=models.PROTECT,
        related_name="versions",
    )
    version_no = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now)
    signer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="signed_versions",
    )
    algorithm = models.CharField(max_length=32)
    certificate_fingerprint = models.CharField(max_length=128)
    payload_hash = models.CharField(max_length=64, db_index=True)
    prev_chain_hash = models.CharField(max_length=64, blank=True, default="")
    chain_hash = models.CharField(max_length=64, db_index=True)
    signature_b64 = models.TextField()
    metadata_json = models.JSONField(default=dict)

    class Meta:
        ordering = ["record_id", "version_no"]
        unique_together = ("record", "version_no")

    def __str__(self):
        return f"{self.record.doc_id} v{self.version_no}"


class SignedDocumentArtifact(models.Model):
    """
    Stored signed artifact for trusted backend-side verification.
    """

    version = models.OneToOneField(
        DocumentVersion,
        on_delete=models.CASCADE,
        related_name="artifact",
    )
    original_filename = models.CharField(max_length=255, blank=True, default="")
    original_bytes = models.BinaryField()
    signature_b64 = models.TextField()
    certificate_pem = models.TextField()
    algorithm = models.CharField(max_length=32)
    hash_hex = models.CharField(max_length=64)
    signed_package_json = models.JSONField(default=dict)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"artifact:{self.version.record.doc_id}:v{self.version.version_no}"
