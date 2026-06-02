from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def set_existing_roles(apps, schema_editor):
    User = apps.get_model(*settings.AUTH_USER_MODEL.split("."))
    UserProfile = apps.get_model("api", "UserProfile")
    admin_ids = set(
        User.objects.filter(models.Q(is_staff=True) | models.Q(is_superuser=True)).values_list("id", flat=True)
    )
    for profile in UserProfile.objects.all():
        profile.role = "admin" if profile.user_id in admin_ids else "user"
        profile.save(update_fields=["role"])


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0007_encrypt_keys_and_audit_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="role",
            field=models.CharField(
                choices=[("admin", "Admin"), ("user", "User")],
                default="user",
                max_length=16,
            ),
        ),
        migrations.CreateModel(
            name="AuditLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("action", models.CharField(choices=[("SIGN", "SIGN"), ("VERIFY", "VERIFY")], max_length=16)),
                ("status", models.CharField(choices=[("SUCCESS", "SUCCESS"), ("FAILED", "FAILED")], max_length=16)),
                ("data_hash", models.CharField(max_length=64)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("failure_reason", models.TextField(blank=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="audit_logs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ["-timestamp"]},
        ),
        migrations.RunPython(set_existing_roles, migrations.RunPython.noop),
    ]
