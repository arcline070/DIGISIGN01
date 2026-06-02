import base64
import hashlib

from cryptography.fernet import Fernet
from django.conf import settings
from django.db import migrations, models


def _fernet():
    env_key = (getattr(settings, "PRIVATE_KEY_FERNET_KEY", "") or "").strip()
    if env_key:
        return Fernet(env_key.encode("utf-8"))
    derived = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_existing_private_keys(apps, schema_editor):
    UserProfile = apps.get_model("api", "UserProfile")
    f = _fernet()
    for profile in UserProfile.objects.all():
        raw = profile.private_key or ""
        if raw.startswith("-----BEGIN"):
            profile.private_key = f.encrypt(raw.encode("utf-8")).decode("utf-8")
            profile.save(update_fields=["private_key"])


def decrypt_existing_private_keys(apps, schema_editor):
    UserProfile = apps.get_model("api", "UserProfile")
    f = _fernet()
    for profile in UserProfile.objects.all():
        raw = profile.private_key or ""
        if raw and not raw.startswith("-----BEGIN"):
            try:
                profile.private_key = f.decrypt(raw.encode("utf-8")).decode("utf-8")
                profile.save(update_fields=["private_key"])
            except Exception:
                continue


def populate_audit_fields(apps, schema_editor):
    SignatureLog = apps.get_model("api", "SignatureLog")
    for log in SignatureLog.objects.all():
        log.data_hash = log.hash_hex
        log.action = "SIGN"
        log.status = "SUCCESS"
        log.save(update_fields=["data_hash", "action", "status"])


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0006_userprofile_replace_userkey"),
    ]

    operations = [
        migrations.AddField(
            model_name="signaturelog",
            name="action",
            field=models.CharField(
                choices=[("SIGN", "SIGN"), ("VERIFY", "VERIFY")],
                default="SIGN",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="signaturelog",
            name="data_hash",
            field=models.CharField(default="", max_length=64),
        ),
        migrations.AddField(
            model_name="signaturelog",
            name="ip_address",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="signaturelog",
            name="status",
            field=models.CharField(
                choices=[("SUCCESS", "SUCCESS"), ("FAILED", "FAILED")],
                default="SUCCESS",
                max_length=16,
            ),
        ),
        migrations.RunPython(populate_audit_fields, migrations.RunPython.noop),
        migrations.RunPython(encrypt_existing_private_keys, decrypt_existing_private_keys),
    ]
