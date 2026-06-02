from rest_framework import serializers

from .models import AuditLog, SignatureLog


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, trim_whitespace=True)
    password = serializers.CharField(write_only=True, min_length=8, style={"input_type": "password"})
    signature_algorithm = serializers.ChoiceField(
        choices=("RSA-SHA256", "ECDSA-P256-SHA256"),
        required=False,
        default="RSA-SHA256",
    )


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, trim_whitespace=True)
    password = serializers.CharField(write_only=True, style={"input_type": "password"})


class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = AuditLog
        fields = (
            "id",
            "username",
            "action",
            "status",
            "timestamp",
            "data_hash",
            "ip_address",
            "failure_reason",
        )
        read_only_fields = fields


class VerifyRequestSerializer(serializers.Serializer):
    """External verification: normalized data + Base64 signature + public key PEM."""

    data = serializers.CharField(allow_blank=True)
    signature = serializers.CharField()
    public_key = serializers.CharField()

    def validate_public_key(self, value: str) -> str:
        if not (value or "").strip():
            raise serializers.ValidationError("Public key is required for verification.")
        return value


class SignatureLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = SignatureLog
        fields = (
            "id",
            "username",
            "action",
            "status",
            "timestamp",
            "data_hash",
            "signature",
            "ip_address",
        )
        read_only_fields = fields


class ExportRequestSerializer(serializers.Serializer):
    format = serializers.ChoiceField(choices=("json", "csv", "excel"))
    log_id = serializers.IntegerField(min_value=1)
